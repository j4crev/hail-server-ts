import {createHash,randomBytes,randomUUID} from "node:crypto";
import {cidForCbor} from "@atproto/common";
import {P256Keypair} from "@atproto/crypto";
import {didForCreateOp,signOperation,validateOperationLog} from "@did-plc/lib";
import {createWebCryptoSigner,createWebCryptoVerifier,decodeBase64Url,encodeBase64Url,signPayload,
  verifySignedPayload,type HailGrant} from "@hailproto/codec";
import {SQL} from "bun";
import {Hono} from "hono";
import {expect,it} from "vitest";
import {registerAccountApiRoutes} from "../src/accounts/routes.js";
import {ManagedAccountTransfer} from "../src/accounts/managed-transfer.js";
import {AccountApiRepository} from "../src/accounts/repository.js";
import {bodyFromText} from "../src/bodies/service.js";
import {ProviderDatabase} from "../src/db/database.js";
import {KeyEncryptor} from "../src/identity/key-encryption.js";
import {ed25519PublicKeyFromDidKey} from "../src/identity/did-key.js";
import {generateAccountKeys,importEd25519PrivateKey} from "../src/identity/keys.js";
import {uuidV7} from "../src/identity/uuid-v7.js";
import {ManagedTransferAuthorization} from "../src/migration/managed-authorization.js";
import {ManagedTransferDelivery} from "../src/migration/managed-delivery.js";
import {ManagedTransferAddressReservation} from "../src/migration/managed-address-selection.js";
import {ManagedMigrationFenceService} from "../src/migration/managed-fence.js";
import {ManagedTransferFencePublisher} from "../src/migration/managed-fence-publisher.js";
import {ManagedMigrationExportService,managedSnapshotSignatureInput,
  validateManagedTransferManifest} from "../src/migration/managed-snapshot.js";
import {ManagedMigrationStageService} from "../src/migration/managed-stage.js";
import {encodeManagedHandshake,managedHandshakeSignatureInput,type ManagedTransferAddressSelection,
  managedHandshakeDigest,verifyManagedProviderHandshake,type ManagedTransferApproval,
  type ManagedTransferGrant} from "../src/migration/managed-handshake.js";
import {ManagedTransferInvitationReceiver} from "../src/migration/managed-invitation-receiver.js";
import {registerManagedTransferRoutes} from "../src/migration/routes.js";
import {PreparedMigrationTarget} from "../src/migration/target-keys.js";
import {OnboardingRepository} from "../src/onboarding/repository.js";
import {withFreshServingGenerations} from "../src/db/serving.js";
import {TransferDeliveryWorker} from "../src/migration/delivery-worker.js";
import {finalRequestWire,parseRequestWire,requestWire,TRANSFER_MEDIA_TYPE} from "../src/migration/wire.js";

const integration=process.env.DATABASE_URL?it:it.skip;

integration("orchestrates the exact managed Offer, reservation, retry and source fence across fixed HTTPS routes",async()=>{
  const admin=new SQL(process.env.DATABASE_URL!),suffix=randomUUID().replaceAll("-",""),sourceSchema=`managed_net_a_${suffix}`,
    targetSchema=`managed_net_b_${suffix}`;await admin.unsafe(`CREATE SCHEMA "${sourceSchema}"`);await admin.unsafe(`CREATE SCHEMA "${targetSchema}"`);
  const scoped=(schema:string)=>{const url=new URL(process.env.DATABASE_URL!);url.searchParams.set("options",`-csearch_path=${schema}`);return url.toString();};
  const source=new ProviderDatabase(scoped(sourceSchema)),target=new ProviderDatabase(scoped(targetSchema));
  try {
    await source.migrate();await target.migrate();const accountId=randomUUID();
    const sourceOrigin="https://a.example.com",sourceBase=`${sourceOrigin}/hail`,targetBase="https://b.example.com/hail";
    const sourceEncryptor=new KeyEncryptor(encodeBase64Url(randomBytes(32))),keys=await generateAccountKeys(accountId,sourceEncryptor);
    const owner=await P256Keypair.create();
    const genesis=await signOperation({type:"plc_operation",prev:null,rotationKeys:[owner.did(),keys.rotationDidKey],
      verificationMethods:{"hail-identity":keys.identityDidKey,"hail-messaging":keys.messagingDidKey},alsoKnownAs:[],
      services:{hail:{type:"HailMessaging",endpoint:sourceBase}}},owner);
    const did=await didForCreateOp(genesis),currentState=(await validateOperationLog(did,[genesis]))!;
    const genesisCid=(await cidForCbor(genesis)).toString();
    await source.sql`INSERT INTO provider_accounts(id,tenant_id,canonical_address,did,onboarding_state,activated_at,
      activation_binding_digest,activation_verification_mode) VALUES (${accountId},${randomUUID()},'alice@a.example.com',${did},
      'active',now(),${randomBytes(32)},'public')`;
    for(const key of keys.keys)await source.sql`INSERT INTO account_keys(account_id,role,algorithm,public_key,encrypted_private_key,
      encryption_nonce,encryption_version,kek_id) VALUES (${accountId},${key.role},${key.algorithm},${key.publicKey},
      ${key.ciphertext},${key.nonce},${key.encryptionVersion},${key.kekId})`;
    await source.sql`INSERT INTO managed_custody_evidence(account_id,owner_recovery_public_key,provider_identity_public_key,
      verification_mode) VALUES (${accountId},${owner.did()},${keys.identityDidKey},'strict-public-v1')`;
    const grantId=uuidV7(),grantee=`did:plc:${"f".repeat(24)}`,grantNow=Math.floor(Date.now()/1000),grant:HailGrant={
      type:"hail.grant",version:1,grant_id:grantId,revision:1,previous:null,grantor:did,grantee,
      scope:[{type:"uncategorized"}],status:"active",issued_at:grantNow,updated_at:grantNow,expires_at:null,
      consent_context:{grantee_address:"peer@peer.example.com",address_binding_hash:{algorithm:"sha-256",value:randomBytes(32)},
        sender_profile_hash:{algorithm:"sha-256",value:randomBytes(32)}},key_id:`${did}#hail-identity`};
    const identityRecord=keys.keys.find(key=>key.role==="hail-identity")!,identitySecret=await sourceEncryptor.decrypt(
      accountId,identityRecord.role,identityRecord.algorithm,identityRecord.publicKey,identityRecord);
    let grantCose:Uint8Array;
    try {grantCose=await signPayload("hail.grant",grant,createWebCryptoSigner(`${did}#hail-identity`,
      await importEd25519PrivateKey(identitySecret)));} finally {identitySecret.fill(0);}
    const grantDigest=new Uint8Array(createHash("sha256").update(grantCose).digest());
    await source.sql`INSERT INTO grant_lineages(grant_id,local_account_id,local_role,grantor_did,grantee_did,
      current_revision,current_digest,current_status) VALUES (${grantId},${accountId},'grantor',${did},${grantee},1,${grantDigest},'active')`;
    await source.sql`INSERT INTO grant_revisions(grant_id,revision,status,issued_at,updated_at,expires_at,previous_digest,
      scope_payload,consent_address_binding_sha256,consent_sender_profile_sha256,cose,representation_digest,
      signing_public_key,signing_plc_document,signing_plc_data,signing_plc_operation_log)
      VALUES (${grantId},1,'active',${grantNow},${grantNow},NULL,NULL,${JSON.stringify(grant.scope)}::jsonb,
        ${grant.consent_context.address_binding_hash.value},${grant.consent_context.sender_profile_hash.value},
        ${grantCose},${grantDigest},${keys.identityDidKey},'{}','{}','[]')`;
    await source.sql`INSERT INTO grant_publications(grant_id,revision,destination_service_base,state)
      VALUES (${grantId},1,'https://peer.example.com/hail','pending')`;
    const bodyBytes=bodyFromText("managed continuity"),bodyHash=new Uint8Array(createHash("sha256").update(bodyBytes).digest()),
      bodyToken=randomBytes(32),bodyTokenHash=new Uint8Array(createHash("sha256").update(bodyToken).digest());
    await source.sql`INSERT INTO detached_bodies(digest,sender_account_id,body_bytes,available_until)
      VALUES (${bodyHash},${accountId},${bodyBytes},${grantNow+7200})`;
    await source.sql`INSERT INTO body_authorizations(token_hash,body_digest,sender_account_id,recipient_did,message_id,
      expires_at,available_until) VALUES (${bodyTokenHash},${bodyHash},${accountId},${grantee},${uuidV7()},
        ${grantNow+7200},${grantNow+7200})`;
    const resolver={async resolve(value:string){if(value!==did)throw new Error("unknown DID");return {did,
      identityDidKey:keys.identityDidKey,messagingDidKey:keys.messagingDidKey,serviceBase:sourceBase,
      evidence:{document:{},data:currentState,log:[genesis],verification:{profile:"strict-public-v1" as const,
        digest:"fixture",operationCid:genesisCid,verifiedAt:new Date().toISOString()}}};}};
    const targetKeys=new PreparedMigrationTarget(target.sql,new KeyEncryptor(encodeBase64Url(randomBytes(32))),targetBase);
    const destination=new Hono(),receiver=new ManagedTransferInvitationReceiver(target.sql,resolver,targetKeys);
    const accounts=new AccountApiRepository(source.sql),credential=await accounts.issue("alice@a.example.com",false,undefined,["account:read","account:write"]);
    const onboarding=new OnboardingRepository(source.sql);
    const authorization=new ManagedTransferAuthorization(source.sql,resolver,sourceBase,onboarding,sourceEncryptor);
    let deliveryAttempts=0;
    const delivery=new ManagedTransferDelivery(source.sql,resolver,sourceBase,
      async request=>++deliveryAttempts===1?new Response(null,{status:503}):
        withFreshServingGenerations(target.sql,()=>destination.fetch(request)),url=>{
      if(url.href!=="https://b.example.com/.well-known/hail/transfers/managed-invitations")throw new Error("wrong target");});
    const fence=new ManagedMigrationFenceService(source.sql,resolver,sourceBase);
    let sourceApp:Hono, fenceAttempts=0;
    const reservations=new ManagedTransferAddressReservation(target.sql,resolver,targetKeys);
    const publisher=new ManagedTransferFencePublisher(target.sql,resolver,targetKeys,async request=>{
      if(++fenceAttempts===1)return new Response(null,{status:503});
      return withFreshServingGenerations(source.sql,()=>sourceApp.fetch(request));
    },url=>{if(url.href!==`${sourceBase}/transfers/managed-requests`)throw new Error("wrong source fence target");});
    registerManagedTransferRoutes(destination,receiver,undefined,reservations,publisher);
    const managed=new ManagedAccountTransfer(source.sql,authorization,delivery,sourceOrigin),app=new Hono();sourceApp=app;
    registerAccountApiRoutes(app,accounts,{} as never,{} as never,sourceOrigin,undefined,undefined,undefined,undefined,managed);
    registerManagedTransferRoutes(app,undefined,undefined,undefined,undefined,fence);
    const now=Math.floor(Date.now()/1000),grantValue:ManagedTransferGrant={type:"hail.managed-transfer-grant",version:1,did,
      nonce:randomUUID(),source_service_base:sourceBase,destination_service_base:targetBase,destination_domain:"b.example.com",
      owner_recovery_key:owner.did(),source_identity_key:keys.identityDidKey,issued_at:now,expires_at:now+3600};
    const bytes=encodeManagedHandshake(grantValue),signed={payloadBytes:bytes,
      signature:await owner.sign(managedHandshakeSignatureInput(grantValue.type,bytes))},body=JSON.stringify({
        payload:encodeBase64Url(signed.payloadBytes),signature:encodeBase64Url(signed.signature)});
    const call=(path:string,method="GET",payload?:string,token=credential.token)=>app.request(`${sourceOrigin}${path}`,{
      method,headers:{Authorization:`Bearer ${token}`,...(payload?{"Content-Type":"application/json"}:{})},...(payload?{body:payload}:{})});
    expect((await call("/api/v1/account/transfers/managed/offer","POST",body,"wrong")).status).toBe(401);
    const firstResponse=await call("/api/v1/account/transfers/managed/offer","POST",body);expect(firstResponse.status).toBe(200);
    const first=await firstResponse.json() as Record<string,any>;expect(first).toMatchObject({type:"hailp.managed-transfer-status",
      phase:"acknowledgement-retained",did,originConfirmed:false,destinationServiceBase:targetBase,offer:null});
    expect(first.acknowledgement).toEqual(expect.objectContaining({payload:expect.any(String),signature:expect.any(String)}));
    const sourceWorker=new TransferDeliveryWorker(source.sql,{async deliver(){throw new Error("portable worker must not claim managed work");}},
      {async publish(){throw new Error("source has no final request");}},delivery);
    const targetWorker=new TransferDeliveryWorker(target.sql,{async deliver(){throw new Error("target has no invitation");}},
      {async publish(){throw new Error("portable final worker must not claim managed work");}},undefined,publisher);
    await expect(sourceWorker.runOnce()).resolves.toBe("managed-invitation");
    const ready=await (await call("/api/v1/account/transfers/managed")).json() as Record<string,any>;
    expect(ready).toMatchObject({phase:"offer-ready",originConfirmed:true});
    expect(ready.offer).toEqual(expect.objectContaining({payload:expect.any(String),signature:expect.any(String)}));
    const retry=await (await call("/api/v1/account/transfers/managed/offer","POST",body)).json();expect(retry).toEqual(ready);
    const offerSigned={payloadBytes:decodeBase64Url(ready.offer.payload),signature:decodeBase64Url(ready.offer.signature)};
    const targetRole=(await target.sql<{messaging_public_key:string}[]>`SELECT messaging_public_key
      FROM prepared_migration_target_keys WHERE did=${did}`)[0]!;
    const offer=await verifyManagedProviderHandshake(offerSigned,"hail.managed-transfer-offer",targetRole.messaging_public_key);
    const selectionValue:ManagedTransferAddressSelection={type:"hail.managed-transfer-address-selection",version:1,did,
      nonce:grantValue.nonce,transfer_id:offer.transfer_id,grant_digest:offer.grant_digest,
      offer_digest:new Uint8Array(await crypto.subtle.digest("SHA-256",Uint8Array.from(offerSigned.payloadBytes))),
      address:"alice@b.example.com",selection_nonce:randomUUID(),issued_at:now,expires_at:now+1800};
    const selectionBytes=encodeManagedHandshake(selectionValue),selectionSigned={payloadBytes:selectionBytes,
      signature:await owner.sign(managedHandshakeSignatureInput(selectionValue.type,selectionBytes))};
    const activeLease=randomUUID();
    await source.sql`INSERT INTO serving_worker_leases(lease_token,account_id,generation)
      VALUES (${activeLease},${accountId},1)`;
    const reserve=()=>withFreshServingGenerations(target.sql,()=>destination.request(
      "https://b.example.com/.well-known/hail/transfers/managed-reservations",{method:"POST",
        headers:{"Content-Type":TRANSFER_MEDIA_TYPE},body:Uint8Array.from(requestWire(selectionSigned))}));
    const reservedResponse=await reserve();expect(reservedResponse.status).toBe(202);
    const reservationSigned=parseRequestWire(new Uint8Array(await reservedResponse.arrayBuffer()));
    expect(fenceAttempts).toBe(1);
    expect((await source.sql`SELECT 1 FROM provider_migration_fences WHERE did=${did}`)).toHaveLength(0);
    await target.sql`UPDATE received_transfer_invitations SET next_final_attempt_at=clock_timestamp()
      WHERE transfer_id=${offer.transfer_id}`;
    await expect(targetWorker.runOnce()).resolves.toBe("managed-final");
    expect(fenceAttempts).toBe(2);
    expect((await source.sql`SELECT 1 FROM provider_migration_fences WHERE did=${did}`)).toHaveLength(0);
    await source.sql`DELETE FROM serving_worker_leases WHERE lease_token=${activeLease}`;
    await target.sql`UPDATE received_transfer_invitations SET next_final_attempt_at=clock_timestamp()
      WHERE transfer_id=${offer.transfer_id}`;
    await expect(targetWorker.runOnce()).resolves.toBe("managed-final");
    expect(fenceAttempts).toBe(3);
    expect((await source.sql`SELECT 1 FROM provider_migration_fences WHERE did=${did}`)).toHaveLength(0);
    await source.sql`UPDATE grant_publications SET state='acknowledged',acknowledged_etag='"grant-v1"',
      acknowledged_at=clock_timestamp() WHERE grant_id=${grantId} AND revision=1`;
    await target.sql`UPDATE received_transfer_invitations SET next_final_attempt_at=clock_timestamp()
      WHERE transfer_id=${offer.transfer_id}`;
    await expect(targetWorker.runOnce()).resolves.toBe("managed-final");
    expect(fenceAttempts).toBe(4);
    const fenceRow=(await source.sql<{source_custody_profile:string;owner_recovery_public_key:string;
      source_identity_public_key:string;destination_identity_public_key:string;state:string}[]>`
      SELECT source_custody_profile,owner_recovery_public_key,source_identity_public_key,
        destination_identity_public_key,state FROM provider_migration_fences WHERE did=${did}`)[0]!;
    expect(fenceRow).toMatchObject({source_custody_profile:"managed",owner_recovery_public_key:owner.did(),
      source_identity_public_key:keys.identityDidKey,destination_identity_public_key:offer.destination_identity_key,state:"fenced"});
    const exporter=new ManagedMigrationExportService(source.sql,onboarding,sourceEncryptor,resolver,sourceBase);
    const exported=await exporter.exportFenced({did,accountId,transferId:offer.transfer_id,destinationServiceBase:targetBase,
      ownerRecoveryPublicKey:owner.did(),sourceIdentityPublicKey:keys.identityDidKey,
      destinationIdentityPublicKey:offer.destination_identity_key,
      destinationRotationPublicKey:offer.destination_rotation_key,
      destinationMessagingPublicKey:offer.destination_messaging_key,state:"fenced"});
    const manifest=validateManagedTransferManifest(exported.bytes);
    expect(manifest).toMatchObject({version:4,custodyProfile:"managed",did,sourceGeneration:1,
      ownerRecoveryPublicKey:owner.did(),sourceIdentityPublicKey:keys.identityDidKey,
      destinationIdentityPublicKey:offer.destination_identity_key});
    expect(manifest.tables.grant_publications).toEqual([expect.objectContaining({grant_id:grantId,revision:1,
      state:"acknowledged",acknowledged_etag:'"grant-v1"'})]);
    const serialized=new TextDecoder().decode(exported.bytes);
    expect(serialized).not.toMatch(/encrypted_private_key|encryption_nonce|kek_id|lease_token|lease_expires_at|"(?:token|secret|credential)"\s*:/);
    expect(manifest.tables.body_authorizations[0]?.token_hash).toBe(`\\x${Buffer.from(bodyTokenHash).toString("hex")}`);
    expect(serialized).not.toContain(Buffer.from(bodyToken).toString("hex"));
    const invalid=(change:(value:any)=>void)=>{const value=JSON.parse(new TextDecoder().decode(exported.bytes));change(value);
      return()=>validateManagedTransferManifest(new TextEncoder().encode(JSON.stringify(value)));};
    expect(invalid(value=>{value.tables.detached_bodies[0].sender_account_id=randomUUID();})).toThrow(/body integrity/);
    expect(invalid(value=>{value.tables.detached_bodies[0].body_bytes=`\\x${Buffer.from(bodyFromText("changed")).toString("hex")}`;}))
      .toThrow(/body integrity/);
    expect(invalid(value=>{value.tables.body_authorizations[0].body_digest=`\\x${"00".repeat(32)}`;}))
      .toThrow(/local provenance/);
    expect(invalid(value=>{value.tables.grant_publications[0].lease_token=randomUUID();})).toThrow(/worker lease/);
    const tampered=JSON.parse(new TextDecoder().decode(exported.bytes)) as Record<string,unknown>;
    tampered.historyCheckpointDigest=encodeBase64Url(randomBytes(32));
    expect(()=>validateManagedTransferManifest(new TextEncoder().encode(JSON.stringify(tampered))))
      .toThrow(/history checkpoint/);
    expect(await crypto.subtle.verify("Ed25519",await ed25519PublicKeyFromDidKey(exported.sourceMessagingPublicKey),
      Uint8Array.from(exported.signature),managedSnapshotSignatureInput(exported.digest))).toBe(true);
    const exportRetry=await exporter.exportFenced({did,accountId,transferId:offer.transfer_id,destinationServiceBase:targetBase,
      ownerRecoveryPublicKey:owner.did(),sourceIdentityPublicKey:keys.identityDidKey,
      destinationIdentityPublicKey:offer.destination_identity_key,
      destinationRotationPublicKey:offer.destination_rotation_key,
      destinationMessagingPublicKey:offer.destination_messaging_key,state:"exported"});
    expect(exportRetry).toEqual(exported);
    const cutover=await signOperation({type:"plc_operation",prev:genesisCid,
      rotationKeys:[owner.did(),offer.destination_rotation_key],verificationMethods:{
        ...currentState.verificationMethods,"hail-identity":offer.destination_identity_key,
        "hail-messaging":offer.destination_messaging_key},alsoKnownAs:currentState.alsoKnownAs,
      services:{...currentState.services,hail:{type:"HailMessaging",endpoint:targetBase}}},owner);
    const cutoverBytes=new TextEncoder().encode(JSON.stringify(cutover)),cutoverCid=(await cidForCbor(cutover)).toString();
    const approval:ManagedTransferApproval={type:"hail.managed-transfer-approval",version:1,did,
      nonce:grantValue.nonce,transfer_id:offer.transfer_id,source_service_base:sourceBase,
      destination_service_base:targetBase,destination_address:selectionValue.address,owner_recovery_key:owner.did(),
      source_identity_key:keys.identityDidKey,destination_rotation_key:offer.destination_rotation_key,
      destination_identity_key:offer.destination_identity_key,destination_messaging_key:offer.destination_messaging_key,
      grant_digest:managedHandshakeDigest(signed.payloadBytes),offer_digest:managedHandshakeDigest(offerSigned.payloadBytes),
      selection_digest:managedHandshakeDigest(selectionSigned.payloadBytes),snapshot_version:4,
      snapshot_digest:exported.digest,history_checkpoint_digest:decodeBase64Url(manifest.historyCheckpointDigest),
      source_generation:manifest.sourceGeneration,previous_operation_cid:genesisCid,operation_cid:cutoverCid,
      issued_at:now,expires_at:now+900};
    const approvalBytes=encodeManagedHandshake(approval),approvalSigned={payloadBytes:approvalBytes,
      signature:await owner.sign(managedHandshakeSignatureInput(approval.type,approvalBytes))};
    const stager=new ManagedMigrationStageService(target.sql,resolver,targetKeys,targetBase,()=>now);
    expect(await stager.stage(exported,approvalSigned,cutoverBytes)).toEqual(manifest);
    const staged=(await target.sql<{state:string;custody_profile:string;owner_recovery_public_key:string;
      source_identity_public_key:string;destination_identity_public_key:string;destination_address:string;
      destination_binding_cose:Uint8Array}[]>`SELECT state,custody_profile,owner_recovery_public_key,
      source_identity_public_key,destination_identity_public_key,destination_address,destination_binding_cose
      FROM pending_migration_imports WHERE transfer_id=${offer.transfer_id}`)[0]!;
    expect(staged).toMatchObject({state:"staged",custody_profile:"managed",owner_recovery_public_key:owner.did(),
      source_identity_public_key:keys.identityDidKey,destination_identity_public_key:offer.destination_identity_key,
      destination_address:selectionValue.address});
    expect((await verifySignedPayload("hail.address-binding",new Uint8Array(staged.destination_binding_cose),
      createWebCryptoVerifier(()=>ed25519PublicKeyFromDidKey(offer.destination_identity_key)))).payload)
      .toMatchObject({did,address:selectionValue.address,key_id:`${did}#hail-identity`});
    const rollback48=await target.sql.reserve();try {
      await expect(rollback48.unsafe(await Bun.file(new URL("../migrations/rollback/0048_managed_migration_approval.sql",import.meta.url)).text()))
        .rejects.toThrow("managed owner approval evidence exists");
    } finally {await rollback48.unsafe("ROLLBACK");rollback48.release();}
    expect((await target.sql<{state:string}[]>`SELECT state FROM prepared_migration_target_keys
      WHERE transfer_id=${offer.transfer_id}`)[0]?.state).toBe("staged");
    expect(await target.sql`SELECT 1 FROM provider_accounts WHERE did=${did}`).toHaveLength(0);
    expect((await source.sql<{state:string}[]>`SELECT state FROM provider_migration_fences
      WHERE transfer_id=${offer.transfer_id}`)[0]?.state).toBe("exported");
    expect(await stager.stage(exported,approvalSigned,cutoverBytes)).toEqual(manifest);
    const changedSnapshot={...exported,bytes:Uint8Array.from(exported.bytes)};
    const snapshotLast=changedSnapshot.bytes.length-1;
    changedSnapshot.bytes[snapshotLast]=(changedSnapshot.bytes[snapshotLast]??0)^1;
    await expect(stager.stage(changedSnapshot,approvalSigned,cutoverBytes)).rejects.toThrow(/digest or signature/);
    const changedApproval={...approval,destination_address:"other@b.example.com"},changedApprovalBytes=encodeManagedHandshake(changedApproval);
    await expect(stager.stage(exported,{payloadBytes:changedApprovalBytes,
      signature:await owner.sign(managedHandshakeSignatureInput(changedApproval.type,changedApprovalBytes))},cutoverBytes))
      .rejects.toThrow(/exact snapshot and handshake/);
    const changedCutover=await signOperation({type:"plc_operation",prev:cutover.prev,
      rotationKeys:cutover.rotationKeys,verificationMethods:cutover.verificationMethods,
      alsoKnownAs:cutover.alsoKnownAs,services:{...cutover.services,
        extra:{type:"OtherService",endpoint:"https://other.example.com"}}},owner);
    await expect(stager.stage(exported,approvalSigned,new TextEncoder().encode(JSON.stringify(changedCutover))))
      .rejects.toThrow(/unapproved PLC state/);
    expect((await source.sql`SELECT 1 FROM provider_migration_exports
      WHERE transfer_id=${offer.transfer_id} AND custody_profile='managed'`)).toHaveLength(1);
    await expect(source.sql`UPDATE account_keys SET public_key=public_key WHERE account_id=${accountId}`)
      .rejects.toThrow(/migration-fenced/);
    const finalRow=(await target.sql<{final_request_bytes:Uint8Array;final_request_signature:Uint8Array}[]>`
      SELECT final_request_bytes,final_request_signature FROM received_transfer_invitations
      WHERE transfer_id=${offer.transfer_id}`)[0]!;
    const requestSigned={payloadBytes:new Uint8Array(finalRow.final_request_bytes),
      signature:new Uint8Array(finalRow.final_request_signature)};
    const exactBody=finalRequestWire(selectionSigned,reservationSigned,requestSigned);
    expect(await fence.previouslyAccepted(requestSigned,selectionSigned,reservationSigned)).toBe(true);
    const exact=await withFreshServingGenerations(source.sql,()=>app.request(`${sourceBase}/transfers/managed-requests`,{
      method:"POST",headers:{"Content-Type":TRANSFER_MEDIA_TYPE},body:Uint8Array.from(exactBody)}));
    expect(exact.status).toBe(204);
    const repeat=await reserve();expect(repeat.status).toBe(200);
    expect(parseRequestWire(new Uint8Array(await repeat.arrayBuffer()))).toEqual(reservationSigned);
    const changedSelection={...selectionValue,address:"other@b.example.com",selection_nonce:randomUUID()},
      changedSelectionBytes=encodeManagedHandshake(changedSelection),changedSelectionSigned={payloadBytes:changedSelectionBytes,
        signature:await owner.sign(managedHandshakeSignatureInput(changedSelection.type,changedSelectionBytes))};
    const changedSelectionResponse=await withFreshServingGenerations(target.sql,()=>destination.request(
      "https://b.example.com/.well-known/hail/transfers/managed-reservations",{method:"POST",
        headers:{"Content-Type":TRANSFER_MEDIA_TYPE},body:Uint8Array.from(requestWire(changedSelectionSigned))}));
    expect(changedSelectionResponse.status).toBe(400);
    const changedReservation={...reservationSigned,payloadBytes:Uint8Array.from(reservationSigned.payloadBytes)};
    const reservationLast=changedReservation.payloadBytes.length-1;
    changedReservation.payloadBytes[reservationLast]=(changedReservation.payloadBytes[reservationLast]??0)^1;
    const changedReservationResponse=await withFreshServingGenerations(source.sql,()=>app.request(
      `${sourceBase}/transfers/managed-requests`,{method:"POST",headers:{"Content-Type":TRANSFER_MEDIA_TYPE},
        body:Uint8Array.from(finalRequestWire(selectionSigned,changedReservation,requestSigned))}));
    expect(changedReservationResponse.status).toBe(400);
    const changedRequest={...requestSigned,payloadBytes:Uint8Array.from(requestSigned.payloadBytes)};
    const requestLast=changedRequest.payloadBytes.length-1;
    changedRequest.payloadBytes[requestLast]=(changedRequest.payloadBytes[requestLast]??0)^1;
    const changedRequestResponse=await withFreshServingGenerations(source.sql,()=>app.request(
      `${sourceBase}/transfers/managed-requests`,{method:"POST",headers:{"Content-Type":TRANSFER_MEDIA_TYPE},
        body:Uint8Array.from(finalRequestWire(selectionSigned,reservationSigned,changedRequest))}));
    expect(changedRequestResponse.status).toBe(400);
    const changed={...grantValue,nonce:randomUUID()},changedBytes=encodeManagedHandshake(changed),changedBody=JSON.stringify({
      payload:encodeBase64Url(changedBytes),signature:encodeBase64Url(await owner.sign(managedHandshakeSignatureInput(changed.type,changedBytes)))});
    expect((await call("/api/v1/account/transfers/managed/offer","POST",changedBody)).status).toBe(409);
    expect((await source.sql`SELECT 1 FROM provider_transfer_authorizations WHERE did=${did} AND custody_profile='managed' AND origin_confirmed_at IS NOT NULL`)).toHaveLength(1);
    expect((await target.sql`SELECT 1 FROM prepared_migration_target_keys WHERE did=${did} AND custody_profile='managed'`)).toHaveLength(1);
    expect((await target.sql`SELECT 1 FROM received_transfer_invitations WHERE did=${did}`)).toHaveLength(1);
  } finally {await source.close();await target.close();await admin.unsafe(`DROP SCHEMA "${sourceSchema}" CASCADE`);
    await admin.unsafe(`DROP SCHEMA "${targetSchema}" CASCADE`);await admin.close();}
},45_000);
