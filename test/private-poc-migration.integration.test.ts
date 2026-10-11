import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { cidForCbor } from "@atproto/common";
import { formatDidDoc, PlcClientError, validateOperationLog, type Operation } from "@did-plc/lib";
import { decodeBase64Url, decodeDeterministic, encodeBase64Url, inspectSignedPayload,
  type HailAddressBinding } from "@hailproto/codec";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createUserVault, unlockUserVault } from "../../hail-user-client-ts/src/vault.js";
import { AccountApiClient } from "../../hail-user-client-ts/src/account-api.js";
import { transferOffer,selectTransferAddress,exportTransferSnapshot,completeAccountTransfer } from "../../hail-user-client-ts/src/account-transfer.js";
import { loginAccount } from "../../hail-user-client-ts/src/account-login.js";
import { AccountAccess } from "../src/accounts/access.js";
import { PrivatePocTransferCompletion } from "../src/migration/poc-completion.js";
import { AccountApiRepository } from "../src/accounts/repository.js";
import { AccountTransfer } from "../src/accounts/transfer.js";
import { registerAccountApiRoutes } from "../src/accounts/routes.js";
import { createApp } from "../src/app.js";
import { ProviderDatabase } from "../src/db/database.js";
import { AddressVerifier } from "../src/discovery/verifier.js";
import { KeyEncryptor } from "../src/identity/key-encryption.js";
import { TransferAddressReservation } from "../src/migration/address-selection.js";
import { PortableMigrationActivation } from "../src/migration/activation.js";
import { MigrationFenceService } from "../src/migration/fence.js";
import { TransferFinalRequestPublisher } from "../src/migration/final-request-publisher.js";
import { TransferInvitationService,type SignedHandshake } from "../src/migration/handshake.js";
import { TransferGrantSubmission } from "../src/migration/grant-submission.js";
import { TransferCancellationService } from "../src/migration/cancellation.js";
import { TransferInvitationDelivery } from "../src/migration/invitation-delivery.js";
import { TransferInvitationReceiver } from "../src/migration/invitation-receiver.js";
import { PrivatePocAddressPublication } from "../src/migration/poc-address-publication.js";
import { PrivatePocCutoverGate } from "../src/migration/poc-cutover-gate.js";
import { PrivatePocPlcSubmission } from "../src/migration/poc-plc-submission.js";
import { registerTransferRoutes } from "../src/migration/routes.js";
import { PreparedMigrationTarget } from "../src/migration/target-keys.js";
import { MigrationTransferService } from "../src/migration/transfer.js";
import { ActivationService } from "../src/onboarding/activation.js";
import { PrivatePocOnboarding } from "../src/onboarding/private-poc.js";
import { OnboardingRepository } from "../src/onboarding/repository.js";
import type { PlcDirectoryClient } from "../src/plc/client.js";
import { PlcHailDidResolver } from "../src/plc/resolver.js";
import type { AppConfig } from "../src/config.js";

const integration = process.env.DATABASE_URL && process.env.TRANSFER_TARGET_DATABASE_URL ? describe : describe.skip;
const registry = "http://plc.fixture:2582";
const oldBase = "https://source.example.com/hail";
const newBase = "https://target.example.com/hail";

integration("private PLC transfer between disposable POC providers", () => {
  let source: ProviderDatabase;
  let target: ProviderDatabase;
  beforeAll(async () => {
    source = new ProviderDatabase(process.env.DATABASE_URL!);
    target = new ProviderDatabase(process.env.TRANSFER_TARGET_DATABASE_URL!);
    await source.migrate();
    await target.migrate();
  });
  afterAll(async () => { if (source) await source.close(); if (target) await target.close(); });

  it("onboards a new user-held DID, transfers its state, and activates against the one private PLC", async () => {
    const log: Operation[] = [];
    let did = "";
    const plc: PlcDirectoryClient = {
      health: async () => ({ status: "ok" }),
      async getOperationLog(value) {
        if (value !== did || !log.length) throw new PlcClientError(404, null, "Unknown POC DID");
        return [...log];
      },
      async getDocumentData(value) {
        const state = await validateOperationLog(value, await this.getOperationLog(value));
        if (!state) throw new Error("Invalid POC PLC history");
        return state;
      },
      async getDocument(value) { return formatDidDoc(await this.getDocumentData(value)); },
      async getAuditableLog(value) {
        return Promise.all((await this.getOperationLog(value)).map(async (operation) => ({
          did: value, operation, cid: (await cidForCbor(operation)).toString(),
          nullified: false, createdAt: new Date().toISOString(),
        })));
      },
      async sendOperation(value, operation) {
        if (!did) {
          did = value;
          if (log.length) throw new Error("Duplicate genesis");
        } else if (value !== did || operation.prev !== (await cidForCbor(log.at(-1)!)).toString()) {
          throw new Error("Private PLC predecessor changed");
        }
        const updated = await validateOperationLog(value, [...log, operation]);
        if (!updated) throw new Error("Invalid private PLC operation");
        log.push(operation);
      },
    };
    const resolver = new PlcHailDidResolver(plc);
    const sourceRepo = new OnboardingRepository(source.sql);
    const targetRepo = new OnboardingRepository(target.sql);
    const sourceEncryptor = new KeyEncryptor(encodeBase64Url(randomBytes(32)));
    const targetEncryptor = new KeyEncryptor(encodeBase64Url(randomBytes(32)));
    const vault = await createUserVault();
    const client = await unlockUserVault(JSON.parse(JSON.stringify(vault.vault)), vault.recoverySecret);
    const sourceAddress = `poc-${randomUUID()}@source.example.com`;
    const sourceOnboarding = new PrivatePocOnboarding(source.sql, plc, sourceEncryptor, registry, oldBase);
    const prepared = await sourceOnboarding.prepare(sourceAddress,
      vault.vault.recovery.publicDidKey, vault.vault.identity.publicDidKey, true);
    const genesis = await client.signPlcOperation({ type: "plc_operation", prev: null,
      rotationKeys: [prepared.userRecoveryKey, prepared.providerRotationKey],
      verificationMethods: { "hail-identity": prepared.userIdentityKey,
        "hail-messaging": prepared.providerMessagingKey }, alsoKnownAs: [],
      services: { hail: { type: "HailMessaging", endpoint: oldBase } },
    });
    await client.bindDid(genesis.did, genesis.operation);
    const now = Math.floor(Date.now() / 1000);
    const oldBinding = await client.signAddressBinding({ type: "hail.address-binding", version: 1,
      address: sourceAddress, did: genesis.did, issued_at: now, expires_at: now + 90 * 86400,
      key_id: `${genesis.did}#hail-identity` });
    expect((await sourceOnboarding.register(prepared.accountId,
      new TextEncoder().encode(JSON.stringify(genesis.operation)), oldBinding)).state)
      .toBe("address-staged");
    const sourcePublished = await sourceRepo.getBindingForAccount(prepared.accountId);
    await new ActivationService(sourceRepo, { async verify() {
      return { address: sourceAddress, did: genesis.did, serviceBase: oldBase,
        messagingDidKey: prepared.providerMessagingKey, identityDidKey: prepared.userIdentityKey,
        plcEvidence: { document: await plc.getDocument(genesis.did),
          data: await plc.getDocumentData(genesis.did), log: await plc.getOperationLog(genesis.did) },
        verifiedAt: new Date(), binding: inspectSignedPayload("hail.address-binding", oldBinding).payload,
        representation: oldBinding, digest: sourcePublished.digest };
    } }, oldBase, "public").activate(prepared.accountId);
    expect((await sourceRepo.getAccount(prepared.accountId)).state).toBe("active");
    const targetKeys = new PreparedMigrationTarget(target.sql, targetEncryptor, newBase);
    const targetReceiver = new TransferInvitationReceiver(target.sql, resolver, targetKeys);
    const sourceFence = new MigrationFenceService(source.sql, resolver, oldBase);
    const sourceRoutes = new Hono();
    registerTransferRoutes(sourceRoutes,
      new TransferInvitationReceiver(source.sql, resolver,
        new PreparedMigrationTarget(source.sql, sourceEncryptor, oldBase)),
      undefined, sourceFence);
    const publisher = new TransferFinalRequestPublisher(target.sql, resolver, targetKeys,
      async (request) => sourceRoutes.fetch(request),
      (url) => { if (url.href !== `${oldBase}/transfers/requests`) throw new Error("Wrong old service"); });
    const targetRoutes = new Hono();
    registerTransferRoutes(targetRoutes, targetReceiver,
      new TransferAddressReservation(target.sql, resolver, targetKeys), undefined, publisher);
    const delivery = new TransferInvitationDelivery(source.sql, resolver, oldBase,
      async (request) => targetRoutes.fetch(request), (url) => {
        if (url.href !== "https://target.example.com/.well-known/hail/transfers/invitations") {
          throw new Error("Wrong new provider domain");
        }
      });
    const accounts=new AccountApiRepository(source.sql),credential=await accounts.issue(sourceAddress,false,undefined,["account:read","account:write"]);
    registerAccountApiRoutes(sourceRoutes,accounts,{} as never,{} as never,"https://source.example.com",undefined,undefined,
      new AccountTransfer(source.sql,new TransferGrantSubmission(source.sql,resolver,oldBase,sourceRepo,sourceEncryptor,
        new TransferInvitationService(source.sql,resolver,oldBase),delivery),
      new TransferCancellationService(source.sql,resolver,oldBase,sourceRepo,sourceEncryptor),"https://source.example.com",
      {fence:sourceFence,snapshots:new MigrationTransferService(source.sql,sourceRepo,sourceEncryptor,resolver,oldBase)}));
    const reader=await accounts.issue(sourceAddress);
    const preparationDir=await mkdtemp("/tmp/opencode/hail-transfer-client-");
    const destinationUsername=`moved-${randomUUID()}`,destinationAddress=`${destinationUsername}@target.example.com`;
    let offered:SignedHandshake,reservation:SignedHandshake,retainedTransferState:string,exportedSnapshot:Record<string,unknown>;
    try {
      const vaultPath=join(preparationDir,"vault.json"),statePath=join(preparationDir,"state.json"),credentialPath=join(preparationDir,"credential.json");
      await writeFile(vaultPath,JSON.stringify({...client.vault,recovery:{...client.vault.recovery,ciphertext:"AA"}}),{mode:0o600});
      await writeFile(credentialPath,JSON.stringify({type:"hailp.api-credential",version:1,provider:"https://source.example.com",...credential}),{mode:0o600});
      const api=await AccountApiClient.fromCredentialFile(credentialPath);
      let loseExport=true;
      const sourceFetch=vi.spyOn(globalThis,"fetch").mockImplementation(async(input,init)=>{
        const request=new Request(input,init);expect(new URL(request.url).origin).toBe("https://source.example.com");
        const response=await sourceRoutes.fetch(request);
        if(loseExport&&response.ok&&new URL(request.url).pathname.endsWith("/export")){loseExport=false;return new Response(null,{status:503});}return response;
      });
      let loseResponse=true;const received:string[]=[];
      const targetFetch=(async(input:RequestInfo|URL,init?:RequestInit)=>{
        const request=new Request(input,init);expect(request.headers.has("Authorization")).toBe(false);
        expect(new URL(request.url).origin).toBe("https://target.example.com");received.push(await request.clone().text());
        const response=await targetRoutes.fetch(request);
        if(loseResponse&&response.ok){loseResponse=false;throw new Error("Destination committed but selection response was lost");}return response;
      }) as typeof fetch;
      try {
        const secret=async()=>encodeBase64Url(vault.recoverySecret);
        const exportRequest=(token:string,transferId:string)=>sourceRoutes.request("https://source.example.com/api/v1/account/transfers/export",{
          method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify({transferId})});
        expect((await exportRequest(credential.token,randomUUID())).status).toBe(409);
        expect((await exportRequest(reader.token,randomUUID())).status).toBe(403);
        expect((await transferOffer(api,"https://target.example.com",vaultPath,statePath,secret)).phase).toBe("offer-ready");
        await expect(selectTransferAddress(api,destinationUsername,vaultPath,statePath,secret,targetFetch)).rejects.toThrow("response was lost");
        expect((await sourceFence.get(genesis.did))?.state).toBe("fenced");
        expect((await selectTransferAddress(api,destinationUsername,vaultPath,statePath,secret,targetFetch)).requestAcknowledged).toBe(true);
        expect(received[0]).toBe(received[1]);
        const saved=JSON.parse(await readFile(statePath,"utf8"));
        offered={payloadBytes:decodeBase64Url(saved.offer.payload),signature:decodeBase64Url(saved.offer.signature)};
        reservation={payloadBytes:decodeBase64Url(saved.reservation.payload),signature:decodeBase64Url(saved.reservation.signature)};
        expect((await exportRequest(credential.token,randomUUID())).status).toBe(409);
        const snapshotPath=join(preparationDir,"snapshot.json");
        await expect(exportTransferSnapshot(api,statePath,snapshotPath)).rejects.toThrow("HTTP 503");
        expect((await sourceFence.get(genesis.did))?.state).toBe("exported");
        expect((await exportTransferSnapshot(api,statePath,snapshotPath)).state).toBe("exported");
        const firstSnapshot=await readFile(snapshotPath);
        await exportTransferSnapshot(api,statePath,snapshotPath);expect(await readFile(snapshotPath)).toEqual(firstSnapshot);
        exportedSnapshot=JSON.parse(firstSnapshot.toString("utf8"));
        retainedTransferState=await readFile(statePath,"utf8");
      }finally{sourceFetch.mockRestore();}
    }finally{await rm(preparationDir,{recursive:true,force:true});}
    const offer = decodeDeterministic(offered.payloadBytes) as unknown as {
      transfer_id: string; destination_rotation_key: string;
      destination_messaging_key: string };
    expect((await sourceFence.get(genesis.did))?.state).toBe("exported");
    const sourceTransfer = new MigrationTransferService(source.sql, sourceRepo,
      sourceEncryptor, resolver, oldBase);
    const signedSnapshot = await sourceTransfer.exportFenced((await sourceFence.get(genesis.did))!);
    expect(exportedSnapshot.manifest).toBe(encodeBase64Url(signedSnapshot.bytes));
    expect(exportedSnapshot.signature).toBe(encodeBase64Url(signedSnapshot.signature));
    const ceremony = await mkdtemp("/tmp/opencode/hail-cutover-client-");
    let operationCid: string;
    const completionStatePath=join(ceremony,"transfer-state.json"),completionSnapshotPath=join(ceremony,"snapshot.json");
    try {
      const paths = { vault: join(ceremony, "vault.json"), snapshot: join(ceremony, "snapshot.json"),
        state:join(ceremony,"transfer-state.json"),
        offer: join(ceremony, "offer.json"), reservation: join(ceremony, "reservation.json"),
        consent: join(ceremony, "consent.json"), operation: join(ceremony, "operation.json"),
        binding: join(ceremony, "binding.cose") };
      await Promise.all([
        writeFile(paths.vault, JSON.stringify(client.vault), { mode: 0o600 }),
        writeFile(paths.state,retainedTransferState,{mode:0o600}),
        writeFile(paths.snapshot, JSON.stringify({ type: "hail.portable-migration-transfer",
          version: 2, manifest: encodeBase64Url(signedSnapshot.bytes),
          digest: encodeBase64Url(signedSnapshot.digest),
          signature: encodeBase64Url(signedSnapshot.signature),
          sourceMessagingPublicKey: signedSnapshot.sourceMessagingPublicKey }), { mode: 0o600 }),
        writeFile(paths.offer, JSON.stringify({ payload: encodeBase64Url(offered.payloadBytes),
          signature: encodeBase64Url(offered.signature) }), { mode: 0o600 }),
        writeFile(paths.reservation, JSON.stringify({ payload: encodeBase64Url(reservation.payloadBytes),
          signature: encodeBase64Url(reservation.signature) }), { mode: 0o600 }),
      ]);
      const runClient = async (operation=paths.operation) => {
        const child = Bun.spawn(["bun", "src/cli/hailp.ts","account","transfer","sign-cutover",
          "--vault",paths.vault,"--state",paths.state,"--snapshot",paths.snapshot,
          "--consent",paths.consent,"--operation",operation,"--binding",paths.binding],
        { cwd: new URL("../../hail-user-client-ts/", import.meta.url).pathname,
          stdin: "pipe", stdout: "pipe", stderr: "pipe" });
        child.stdin.write(`${encodeBase64Url(vault.recoverySecret)}\n`);
        child.stdin.end();
        const [code,stdout,stderr]=await Promise.all([child.exited,new Response(child.stdout).text(),new Response(child.stderr).text()]);
        expect(stdout+stderr).not.toContain(encodeBase64Url(vault.recoverySecret));
        if(code!==0)throw new Error(stderr);
      };
      await runClient();
      await expect(runClient(join(ceremony,"competing-operation.json"))).rejects.toThrow("paths changed");
      const firstOperation = await readFile(paths.operation);
      const firstConsent = await readFile(paths.consent);
      const firstBinding = await readFile(paths.binding);
      await rm(paths.operation);
      await expect(runClient()).rejects.toThrow("restore the originals");
      await writeFile(paths.operation,firstOperation,{mode:0o600});
      const originalSnapshot=await readFile(paths.snapshot);
      await writeFile(paths.snapshot,JSON.stringify({...JSON.parse(originalSnapshot.toString("utf8")),digest:encodeBase64Url(new Uint8Array(32))}));
      await expect(runClient()).rejects.toThrow("snapshot digest mismatch");
      await writeFile(paths.snapshot,originalSnapshot);
      await runClient();
      expect(await readFile(paths.operation)).toEqual(firstOperation);
      expect(await readFile(paths.consent)).toEqual(firstConsent);
      expect(await readFile(paths.binding)).toEqual(firstBinding);
      const legacy=Bun.spawn(["bun","src/cli/sign-private-poc-cutover.ts",paths.vault,paths.snapshot,paths.offer,paths.reservation,
        paths.consent,paths.operation,paths.binding],{cwd:new URL("../../hail-user-client-ts/",import.meta.url).pathname,stdin:"pipe",stdout:"pipe",stderr:"pipe"});
      legacy.stdin.write(`${encodeBase64Url(vault.recoverySecret)}\n`);legacy.stdin.end();
      expect(await legacy.exited,await new Response(legacy.stderr).text()).toBe(0);
      expect(await readFile(paths.operation)).toEqual(firstOperation);expect(await readFile(paths.consent)).toEqual(firstConsent);
      operationCid = (await cidForCbor(JSON.parse(firstOperation.toString("utf8")) as Operation)).toString();
    } catch(error) {await rm(ceremony,{recursive:true,force:true});throw error;}
    try {
    const targetTransfer = new MigrationTransferService(target.sql, sourceRepo,
      targetEncryptor, resolver, newBase);
    await expect(sourceFence.releaseBeforeExport(genesis.did, offer.transfer_id))
      .rejects.toThrow("Only an unexported");
    const lostResponsePlc = { ...plc, async sendOperation(value: string, operation: Operation) {
      await plc.sendOperation(value, operation);
      throw new Error("PLC committed, but its response was lost");
    } };
    const submission = new PrivatePocPlcSubmission(target.sql, lostResponsePlc, registry, newBase);
    const gate = new PrivatePocCutoverGate(target.sql, { origin: registry,
      resolver, audit: (value) => plc.getAuditableLog(value) }, registry, newBase);
    const publication=new PrivatePocAddressPublication(target.sql,resolver,gate,registry,newBase);
    const config = { publicOrigin: "https://target.example.com", providerId: "target",
      hailServiceBase: newBase } as AppConfig;
    const app = createApp(config, { discoveryStore: targetRepo,accountAccess:{access:new AccountAccess(target.sql,resolver,"https://target.example.com"),sql:target.sql},
      async checkReadiness() { return { ready: true }; } });
    const targetAccounts=new AccountApiRepository(target.sql);
    registerAccountApiRoutes(app,targetAccounts,{} as never,{} as never,"https://target.example.com");
    let addressAvailable=false;
    const verifier = new AddressVerifier(plc, async (request) => {if(!addressAvailable)throw new Error("Destination HTTPS unavailable");return app.fetch(request);}, (url) => {
      if (url.origin !== "https://target.example.com") throw new Error("Unexpected Hail address domain");
    });
    const activation = new PortableMigrationActivation(target.sql, targetEncryptor, resolver,
      gate, verifier, newBase, registry, undefined, "private-poc");
    let expiryProbed=false;
    const completion=new PrivatePocTransferCompletion(target.sql,targetTransfer,{async submit(id){
      if(!expiryProbed){expiryProbed=true;const clock=vi.spyOn(Date,"now").mockReturnValue(Date.now()+7200000);
        try {await expect(submission.submit(id)).rejects.toThrow("stale");expect(log).toHaveLength(1);}finally{clock.mockRestore();}}
      return submission.submit(id);
    }},publication,activation,newBase);
    registerTransferRoutes(app,targetReceiver,undefined,undefined,undefined,undefined,undefined,undefined,undefined,completion);
    const retirementRoutes=new Hono();
    registerTransferRoutes(retirementRoutes,new TransferInvitationReceiver(source.sql,resolver,new PreparedMigrationTarget(source.sql,sourceEncryptor,oldBase)),
      undefined,sourceFence,undefined,undefined,undefined,undefined,undefined,completion);
    let loseActive=true,loseRetirement=true;const destinationRequests:string[]=[];
    const completionTransport=(async(input:RequestInfo|URL,init?:RequestInit)=>{
      const request=new Request(input,init);expect(request.headers.has("Authorization")).toBe(false);
      if(new URL(request.url).origin==="https://target.example.com") {
        destinationRequests.push(await request.clone().text());const response=await app.fetch(request);
        if(loseActive&&response.ok){loseActive=false;return new Response(null,{status:503});}return response;
      }
      expect(request.url).toBe("https://source.example.com/.well-known/hail/transfers/retirements");
      const response=await retirementRoutes.fetch(request);
      if(loseRetirement&&response.ok){loseRetirement=false;return new Response(null,{status:503});}return response;
    }) as typeof fetch;
    const complete=()=>completeAccountTransfer(completionStatePath,completionSnapshotPath,completionTransport);
    await expect(complete()).rejects.toThrow("HTTP 400");
    expect(await targetRepo.getAccountByDid(genesis.did)).toBeNull();
    expect((await sourceFence.get(genesis.did))?.state).toBe("exported");
    expect(log).toHaveLength(2);addressAvailable=true;
    await expect(complete()).rejects.toThrow("HTTP 503");
    expect((await targetRepo.getAccountByDid(genesis.did))?.state).toBe("active");
    const clock=vi.spyOn(Date,"now").mockReturnValue(Date.now()+7200000);
    try {await expect(complete()).rejects.toThrow("source retirement is unconfirmed");
      expect(await complete()).toMatchObject({destinationActive:true,sourceRetired:true,operationCid});}
    finally{clock.mockRestore();}
    expect(destinationRequests.every(bytes=>bytes===destinationRequests[0])).toBe(true);
    const saved=JSON.parse(await readFile(completionStatePath,"utf8"));expect(saved.retired).toBe(true);expect(saved.activationReceipt).toBeDefined();
    const request=JSON.parse(destinationRequests[0]!);request.binding=encodeBase64Url(new Uint8Array([1]));
    const changed=await app.request("https://target.example.com/.well-known/hail/transfers/completions",{method:"POST",headers:{"Content-Type":"application/hail-transfer+json"},body:JSON.stringify(request)});
    expect(changed.status).toBe(400);
    const webfinger=await app.request(`https://target.example.com/.well-known/webfinger?resource=${encodeURIComponent(`acct:${destinationAddress}`)}&rel=${encodeURIComponent("https://hailproto.com/rel/address-binding")}`);
    expect(webfinger.status).toBe(200);
    const receipt = await activation.issueReceipt(offer.transfer_id);
    await sourceFence.retire(genesis.did, offer.transfer_id, receipt);
    await sourceFence.retire(genesis.did, offer.transfer_id, receipt);
    await expect(sourceFence.retire(genesis.did, offer.transfer_id,
      { ...receipt, signature: new Uint8Array(64) })).rejects.toThrow();
    expect((await sourceFence.get(genesis.did))?.state).toBe("retired");
    expect(await sourceRepo.findPublishedByAddress(sourceAddress)).toBeNull();
    expect(await targetRepo.findPublishedByAddress(destinationAddress)).not.toBeNull();
    expect((await targetRepo.getAccountByDid(genesis.did))?.state).toBe("active");
    expect(log).toHaveLength(2);
    expect(await target.sql`SELECT canonical_address FROM provider_accounts
      WHERE did = ${genesis.did}`).toHaveLength(1);
    const loginFetch=vi.spyOn(globalThis,"fetch").mockImplementation(async(input,init)=>{
      const request=new Request(input,init);expect(new URL(request.url).origin).toBe("https://target.example.com");return app.fetch(request);
    });
    try {
      const credentialPath=join(ceremony,"destination-credential.json"),loginState=join(ceremony,"destination-login.json");
      await loginAccount("https://target.example.com",genesis.did,"identity",["account:read"],join(ceremony,"vault.json"),loginState,credentialPath,async()=>encodeBase64Url(vault.recoverySecret));
      const ownerApi=await AccountApiClient.fromCredentialFile(credentialPath);expect((await ownerApi.account()).did).toBe(genesis.did);
      const acquired=JSON.parse(await readFile(credentialPath,"utf8"));expect(acquired.token).not.toBe(credential.token);
      expect(await new AccountApiRepository(source.sql).authenticate(`Bearer ${acquired.token}`)).toBeNull();
    }finally{loginFetch.mockRestore();}
    }finally{await rm(ceremony,{recursive:true,force:true});vault.recoverySecret.fill(0);}
  });
});
