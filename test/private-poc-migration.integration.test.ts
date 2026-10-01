import { createHash, randomBytes, randomUUID } from "node:crypto";
import { cidForCbor } from "@atproto/common";
import { formatDidDoc, PlcClientError, validateOperationLog, type Operation } from "@did-plc/lib";
import { decodeDeterministic, encodeBase64Url, inspectSignedPayload,
  type HailAddressBinding } from "@hailproto/codec";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createUserVault, unlockUserVault } from "../../hail-user-client-ts/src/vault.js";
import { createApp } from "../src/app.js";
import { ProviderDatabase } from "../src/db/database.js";
import { AddressVerifier } from "../src/discovery/verifier.js";
import { KeyEncryptor } from "../src/identity/key-encryption.js";
import { importEd25519PrivateKey } from "../src/identity/keys.js";
import { TransferAddressReservation } from "../src/migration/address-selection.js";
import { PortableMigrationActivation } from "../src/migration/activation.js";
import { MigrationFenceService } from "../src/migration/fence.js";
import { TransferFinalRequestPublisher } from "../src/migration/final-request-publisher.js";
import { TransferInvitationService, handshakeDigest,
  type TransferGrant, type TransferAddressSelection } from "../src/migration/handshake.js";
import { TransferInvitationDelivery } from "../src/migration/invitation-delivery.js";
import { TransferInvitationReceiver } from "../src/migration/invitation-receiver.js";
import { PrivatePocAddressPublication } from "../src/migration/poc-address-publication.js";
import { PrivatePocCutoverGate } from "../src/migration/poc-cutover-gate.js";
import { PrivatePocPlcSubmission } from "../src/migration/poc-plc-submission.js";
import { registerTransferRoutes } from "../src/migration/routes.js";
import { PreparedMigrationTarget } from "../src/migration/target-keys.js";
import { MigrationTransferService } from "../src/migration/transfer.js";
import { parseRequestWire, requestWire, TRANSFER_MEDIA_TYPE } from "../src/migration/wire.js";
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
    const sourceKey = await sourceRepo.getKey(prepared.accountId, "hail-messaging");
    const decrypted = await sourceEncryptor.decrypt(prepared.accountId, sourceKey.role,
      sourceKey.algorithm, sourceKey.publicKey, sourceKey);
    const grantPayload: TransferGrant = { type: "hail.transfer-grant", version: 1,
      did: genesis.did, nonce: randomUUID(), source_service_base: oldBase,
      destination_service_base: newBase, destination_domain: "target.example.com",
      issued_at: now, expires_at: now + 3600 };
    const userGrant = await client.signTransferGrant(grantPayload);
    let invitation;
    try { invitation = await new TransferInvitationService(source.sql, resolver, oldBase)
      .issue(userGrant, await importEd25519PrivateKey(decrypted)); }
    finally { decrypted.fill(0); }
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
    const offered = await delivery.deliver(genesis.did);
    const offer = decodeDeterministic(offered.payloadBytes) as unknown as {
      transfer_id: string; destination_rotation_key: string;
      destination_messaging_key: string };
    const destinationAddress = `moved-${randomUUID()}@target.example.com`;
    const chosen: TransferAddressSelection = { type: "hail.transfer-address-selection", version: 1,
      did: genesis.did, nonce: grantPayload.nonce, transfer_id: offer.transfer_id,
      grant_digest: handshakeDigest(userGrant.payloadBytes), offer_digest: handshakeDigest(offered.payloadBytes),
      address: destinationAddress, selection_nonce: randomUUID(),
      issued_at: now, expires_at: now + 1800 };
    const selected = await client.signTransferAddressSelection(chosen);
    const selectionResponse = await targetRoutes.request(
      "https://target.example.com/.well-known/hail/transfers/reservations",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(requestWire(selected)) });
    expect(selectionResponse.status).toBe(200);
    const reservation = parseRequestWire(new Uint8Array(await selectionResponse.arrayBuffer()));
    expect((await sourceFence.get(genesis.did))?.state).toBe("fenced");
    const sourceTransfer = new MigrationTransferService(source.sql, sourceRepo,
      sourceEncryptor, resolver, oldBase);
    const signedSnapshot = await sourceTransfer.exportFenced((await sourceFence.get(genesis.did))!);
    const cutover = await client.signPlcOperation({ type: "plc_operation",
      prev: (await cidForCbor(genesis.operation)).toString(),
      rotationKeys: [prepared.userRecoveryKey, offer.destination_rotation_key],
      verificationMethods: { "hail-identity": prepared.userIdentityKey,
        "hail-messaging": offer.destination_messaging_key }, alsoKnownAs: [],
      services: { hail: { type: "HailMessaging", endpoint: newBase } },
    });
    const consent = await client.signMigrationConsent({ type: "hail.portable-migration-consent",
      version: 1, did: genesis.did, transfer_id: offer.transfer_id,
      snapshot_digest: signedSnapshot.digest,
      plc_operation_sha256: new Uint8Array(createHash("sha256").update(cutover.dagCbor).digest()),
      source_service_base: oldBase, destination_service_base: newBase,
      destination_address: destinationAddress,
      destination_rotation_key: offer.destination_rotation_key,
      destination_messaging_key: offer.destination_messaging_key,
      user_recovery_key: prepared.userRecoveryKey, user_identity_key: prepared.userIdentityKey,
      created_at: now, expires_at: now + 3600,
    });
    const binding: HailAddressBinding = { type: "hail.address-binding", version: 1,
      address: destinationAddress, did: genesis.did, issued_at: now,
      expires_at: now + 90 * 86400, key_id: `${genesis.did}#hail-identity` };
    const destinationBinding = await client.signAddressBinding(binding);
    const targetTransfer = new MigrationTransferService(target.sql, sourceRepo,
      targetEncryptor, resolver, newBase);
    await targetTransfer.stageImport(signedSnapshot, consent,
      new TextEncoder().encode(JSON.stringify(cutover.operation)), destinationBinding);
    expect(await new PrivatePocPlcSubmission(target.sql, plc, registry, newBase)
      .submit(offer.transfer_id)).toBe(cutover.cid);
    const gate = new PrivatePocCutoverGate(target.sql, { origin: registry,
      resolver, audit: (value) => plc.getAuditableLog(value) }, registry, newBase);
    expect((await gate.assess(offer.transfer_id)).eligible).toBe(true);
    const published = await new PrivatePocAddressPublication(target.sql, resolver, gate,
      registry, newBase).publish(offer.transfer_id);
    const config = { publicOrigin: "https://target.example.com", providerId: "target",
      hailServiceBase: newBase } as AppConfig;
    const app = createApp(config, { discoveryStore: targetRepo, async checkReadiness() { return { ready: true }; } });
    const webfinger = await app.request(`https://target.example.com/.well-known/webfinger?resource=${
      encodeURIComponent(`acct:${destinationAddress}`)}&rel=${encodeURIComponent(
      "https://hailproto.com/rel/address-binding")}`);
    expect(webfinger.status).toBe(200);
    const verifier = new AddressVerifier(plc, async (request) => app.fetch(request), (url) => {
      if (url.origin !== "https://target.example.com") throw new Error("Unexpected Hail address domain");
    });
    const activation = new PortableMigrationActivation(target.sql, targetEncryptor, resolver,
      gate, verifier, newBase, registry, undefined, "private-poc");
    expect(await activation.activate(offer.transfer_id)).toMatchObject({ did: genesis.did });
    const receipt = await activation.issueReceipt(offer.transfer_id);
    await sourceFence.retire(genesis.did, offer.transfer_id, receipt);
    expect((await sourceFence.get(genesis.did))?.state).toBe("retired");
    expect((await targetRepo.getAccountByDid(genesis.did))?.state).toBe("active");
    expect(log).toHaveLength(2);
    expect(published).toMatch(/^[0-9a-f-]{36}$/);
    expect(await target.sql`SELECT canonical_address FROM provider_accounts
      WHERE did = ${genesis.did}`).toHaveLength(1);
    vault.recoverySecret.fill(0);
  });
});
