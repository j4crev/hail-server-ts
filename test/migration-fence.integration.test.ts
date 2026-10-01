import { createHash, randomBytes, randomUUID } from "node:crypto";
import { cidForCbor } from "@atproto/common";
import { P256Keypair } from "@atproto/crypto";
import { didForCreateOp, signOperation, validateOperationLog, type Operation } from "@did-plc/lib";
import { createWebCryptoSigner, encodeBase64Url, inspectSignedPayload, signPayload, type HailAddressBinding, type HailEnvelope, type HailGrant, type HailSenderProfile } from "@hailproto/codec";
import * as dagCbor from "@ipld/dag-cbor";
import { base58btc } from "multiformats/bases/base58";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Hono } from "hono";
import type { ProviderDatabase } from "../src/db/database.js";
import { BodyRepository } from "../src/bodies/repository.js";
import { bodyFromText } from "../src/bodies/service.js";
import { EnvelopeRepository } from "../src/envelopes/repository.js";
import { KeyEncryptor } from "../src/identity/key-encryption.js";
import { generateAccountKeys, importEd25519PrivateKey } from "../src/identity/keys.js";
import { uuidV7 } from "../src/identity/uuid-v7.js";
import { MigrationFenceService } from "../src/migration/fence.js";
import { MigrationTransferService, type SignedTransferSnapshot } from "../src/migration/transfer.js";
import type { HailDidResolver, ResolvedHailDid } from "../src/plc/resolver.js";
import { signPortableMigrationConsent, type SignedPortableConsent } from "../src/migration/consent.js";
import { GrantRepository } from "../src/grants/repository.js";
import { DeliveryRepository } from "../src/delivery/repository.js";
import type { DeliveryClaim } from "../src/delivery/repository.js";
import { DeliveryStatusSigner } from "../src/delivery/status.js";
import { TerminalStatusPublisher } from "../src/delivery/status-publisher.js";
import { OnboardingRepository } from "../src/onboarding/repository.js";
import { PortableCutoverGate, type IndependentPlcObserver } from "../src/migration/cutover-gate.js";
import { PrivatePocCutoverGate } from "../src/migration/poc-cutover-gate.js";
import { signMonitorAttestation } from "../src/migration/monitor-attestation.js";
import { PreparedMigrationTarget } from "../src/migration/target-keys.js";
import { PortableMigrationActivation } from "../src/migration/activation.js";
import { handshakeDigest, signHandshake, TransferInvitationService, type SignedHandshake,
  type TransferGrant, type TransferAddressSelection } from "../src/migration/handshake.js";
import { TransferInvitationReceiver } from "../src/migration/invitation-receiver.js";
import { TransferInvitationDelivery } from "../src/migration/invitation-delivery.js";
import { TransferAddressReservation } from "../src/migration/address-selection.js";
import { TransferFinalRequestPublisher } from "../src/migration/final-request-publisher.js";
import { TransferGrantSubmission } from "../src/migration/grant-submission.js";
import { TransferDeliveryWorker } from "../src/migration/delivery-worker.js";
import { registerTransferRoutes } from "../src/migration/routes.js";
import { invitationWire, TRANSFER_MEDIA_TYPE } from "../src/migration/wire.js";
import { decodeDeterministic } from "@hailproto/codec";
import { DeliveryWorker } from "../src/delivery/worker.js";

const integration = process.env.DATABASE_URL && process.env.TRANSFER_TARGET_DATABASE_URL ? describe : describe.skip;
const sourceBase = "https://source.example.com/hail";
const targetBase = "https://target.example.com/hail";
const remoteDid = `did:plc:${"b".repeat(24)}`;

integration("fenced transfer and concurrent cutover", () => {
  const id = randomUUID();
  const grantId = uuidV7();
  const messageId = uuidV7();
  const terminalMessageId = uuidV7();
  const encryption = new KeyEncryptor("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  const targetEncryption = new KeyEncryptor(encodeBase64Url(new Uint8Array(32).fill(1)));
  let source: ProviderDatabase;
  let target: ProviderDatabase;
  let did: string;
  let resolver: HailDidResolver;
  let fenceService: MigrationFenceService;
  let transferSource: MigrationTransferService;
  let transferTarget: MigrationTransferService;
  let replyableEnvelope: Uint8Array;
  let bodyBytes: Uint8Array;
  let incoming: HailEnvelope;
  let remotePrivateKey: CryptoKey;
  let initialGrant: HailGrant;
  let initialGrantDigest: Uint8Array;
  let identityPrivateKey: CryptoKey;
  let userRecoveryPublicKey: string;
  let userRecoveryPrivateKey: P256Keypair;
  let sourceProviderRotationKey: P256Keypair;
  let genesisOperation: Operation;
  let signedCutoverOperation: Operation;
  let monitorPrivateKey: CryptoKey;
  let monitorPublicKey: string;
  let userIdentityPublicKey: string;
  let destinationRotationPublicKey: string;
  let destinationMessagingPublicKey: string;
  let targetTransferId: string;
  let claimedDelivery: DeliveryClaim;
  let terminalCose: Uint8Array;
  let destinationBinding: Uint8Array;
  let cutoverClock: number;
  let targetGate: PortableCutoverGate;
  let signedRequest: SignedHandshake;
  let signedOffer: SignedHandshake;
  let signedSelection: SignedHandshake;
  let signedReservation: SignedHandshake;
  let userGrant: SignedHandshake;
  let invitation: SignedHandshake;
  let destinationRoutes: Hono;
  let sourceRoutes: Hono;
  let originDelivery: TransferInvitationDelivery;
  let addressReservation: TransferAddressReservation;
  let targetPublisher: TransferFinalRequestPublisher;
  const selectedAddress = `alice-${id}@target.example.com`;

  beforeAll(async () => {
    const { ProviderDatabase } = await import("../src/db/database.js");
    source = new ProviderDatabase(process.env.DATABASE_URL!);
    target = new ProviderDatabase(process.env.TRANSFER_TARGET_DATABASE_URL!);
    await source.migrate();
    await target.migrate();
    const keys = await generateAccountKeys(id, encryption);
    sourceProviderRotationKey = keys.rotationKey;
    const userRecovery = await P256Keypair.create({ exportable: true });
    userRecoveryPrivateKey = userRecovery;
    userRecoveryPublicKey = userRecovery.did();
    userIdentityPublicKey = keys.identityDidKey;
    identityPrivateKey = keys.identityPrivateKey;
    const unsigned = { type: "plc_operation" as const,
      rotationKeys: [userRecoveryPublicKey, keys.rotationDidKey],
      verificationMethods: { "hail-identity": keys.identityDidKey, "hail-messaging": keys.messagingDidKey },
      alsoKnownAs: [], services: { hail: { type: "HailMessaging", endpoint: sourceBase } }, prev: null };
    const operation = await signOperation(unsigned, userRecovery);
    genesisOperation = operation;
    did = await didForCreateOp(operation);
    const operationCid = (await cidForCbor(operation)).toString();
    const expectedState = { did, rotationKeys: unsigned.rotationKeys,
      verificationMethods: unsigned.verificationMethods, alsoKnownAs: unsigned.alsoKnownAs,
      services: unsigned.services };
    expect(await validateOperationLog(did, [operation])).toEqual(expectedState);
    const evidence = { document: {}, data: expectedState, log: [operation] };
    resolver = { async resolve(value): Promise<ResolvedHailDid> {
      if (value !== did) throw new Error("Unknown DID");
      return { did, identityDidKey: keys.identityDidKey, messagingDidKey: keys.messagingDidKey,
        serviceBase: sourceBase, evidence };
    } };
    fenceService = new MigrationFenceService(source.sql, resolver, sourceBase);
    const accounts = { getKey: async (_accountId: string, role: "plc-rotation" | "hail-identity" | "hail-messaging") => {
      const key = keys.keys.find((entry) => entry.role === role);
      if (!key) throw new Error("Missing key");
      return { ...key, accountId: id };
    } };
    transferSource = new MigrationTransferService(source.sql, accounts, encryption, resolver, sourceBase);
    transferTarget = new MigrationTransferService(target.sql, accounts, targetEncryption, resolver, targetBase);
    await source.sql`
      INSERT INTO provider_accounts (id, tenant_id, canonical_address, did, onboarding_state,
        activated_at, activation_binding_digest, activation_verification_mode)
      VALUES (${id}, ${randomUUID()}, ${`migration-${id}@example.com`}, ${did}, 'active', now(),
        ${randomBytes(32)}, 'public')
    `;
    for (const key of keys.keys.filter((entry) => entry.role !== "hail-identity")) {
      await source.sql`
        INSERT INTO account_keys (account_id, role, algorithm, public_key, encrypted_private_key,
          encryption_nonce, encryption_version, kek_id)
        VALUES (${id}, ${key.role}, ${key.algorithm}, ${key.publicKey}, ${key.ciphertext},
          ${key.nonce}, ${key.encryptionVersion}, ${key.kekId})
      `;
    }
    const monitorPair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    monitorPrivateKey = monitorPair.privateKey;
    const monitorKey = new Uint8Array(34);
    monitorKey.set([0xed, 0x01]);
    monitorKey.set(new Uint8Array(await crypto.subtle.exportKey("raw", monitorPair.publicKey)), 2);
    monitorPublicKey = `did:key:${base58btc.encode(monitorKey)}`;
    await source.sql`
      INSERT INTO portable_custody_evidence (account_id, user_recovery_public_key,
        user_identity_public_key, monitor_origin, monitor_public_key,
        monitor_confirmed_at, backup_confirmed_at)
      VALUES (${id}, ${userRecoveryPublicKey}, ${userIdentityPublicKey},
        'https://monitor.example.com', ${monitorPublicKey}, now(), now())
    `;
    const forbiddenIdentity = keys.keys.find((key) => key.role === "hail-identity")!;
    await expect(source.sql`
      INSERT INTO account_keys (account_id, role, algorithm, public_key, encrypted_private_key,
        encryption_nonce, encryption_version, kek_id)
      VALUES (${id}, ${forbiddenIdentity.role}, ${forbiddenIdentity.algorithm},
        ${forbiddenIdentity.publicKey}, ${forbiddenIdentity.ciphertext},
        ${forbiddenIdentity.nonce}, ${forbiddenIdentity.encryptionVersion}, ${forbiddenIdentity.kekId})
    `).rejects.toThrow("Portable custody forbids");
    await source.sql`
      INSERT INTO plc_operation_evidence (id, account_id, did, operation_cid, registry_origin,
        signed_operation, signed_operation_bytes, dag_cbor, expected_state, submission_state)
      VALUES (${randomUUID()}, ${id}, ${did}, ${operationCid}, 'http://plc.fixture:2582',
        ${JSON.stringify(operation)}::jsonb, ${new TextEncoder().encode(JSON.stringify(operation))},
        ${new Uint8Array(dagCbor.encode(operation))}, ${JSON.stringify(expectedState)}::jsonb, 'verified')
    `;
    const now = Math.floor(Date.now() / 1000);
    const consentHash = new Uint8Array(randomBytes(32));
    const grant: HailGrant = { type: "hail.grant", version: 1, grant_id: grantId,
      revision: 1, previous: null, grantor: did, grantee: remoteDid,
      scope: [{ type: "categories", values: ["updates"] }], status: "active",
      issued_at: now, updated_at: now, expires_at: now + 10 * 86400,
      consent_context: { grantee_address: "remote@example.com",
        address_binding_hash: { algorithm: "sha-256", value: consentHash },
        sender_profile_hash: { algorithm: "sha-256", value: consentHash } },
      key_id: `${did}#hail-identity`,
    };
    const signedGrant = await signPayload("hail.grant", grant,
      createWebCryptoSigner(grant.key_id, keys.identityPrivateKey));
    const grantDigest = new Uint8Array(createHash("sha256").update(signedGrant).digest());
    initialGrant = grant;
    initialGrantDigest = grantDigest;
    await source.sql`
      INSERT INTO grant_lineages (grant_id, local_account_id, local_role, grantor_did,
        grantee_did, current_revision, current_digest, current_status)
      VALUES (${grantId}, ${id}, 'grantor', ${did}, ${remoteDid}, 1, ${grantDigest}, 'active')
    `;
    await source.sql`
      INSERT INTO grant_revisions (grant_id, revision, status, issued_at, updated_at, expires_at,
        previous_digest, scope_payload, consent_address_binding_sha256,
        consent_sender_profile_sha256, cose, representation_digest, signing_public_key,
        signing_plc_document, signing_plc_data, signing_plc_operation_log)
      VALUES (${grantId}, 1, 'active', ${now}, ${now}, ${now + 10 * 86400}, NULL,
        ${JSON.stringify([{ type: "categories", values: ["updates"] }])}::jsonb,
        ${consentHash}, ${consentHash}, ${signedGrant}, ${grantDigest},
        'fixture', '{}'::jsonb, '{}'::jsonb, '[]'::jsonb)
    `;
    await source.sql`INSERT INTO grant_publications (grant_id, revision, destination_service_base)
      VALUES (${grantId}, 1, 'https://remote.example.com/hail')`;
    const body = await new BodyRepository(source.sql).publish(did, bodyFromText("Fenced transfer"));
    bodyBytes = body.bytes;
    const key = keys.keys.find((entry) => entry.role === "hail-messaging")!;
    const plaintext = await encryption.decrypt(id, key.role, key.algorithm, key.publicKey, key);
    const privateKey = await importEd25519PrivateKey(plaintext);
    plaintext.fill(0);
    const transferGrant: TransferGrant = { type: "hail.transfer-grant", version: 1, did,
      nonce: randomUUID(), source_service_base: sourceBase, destination_service_base: targetBase,
      destination_domain: "target.example.com",
      issued_at: now, expires_at: now + 3600 };
    userGrant = await signHandshake(transferGrant, identityPrivateKey);
    invitation = await new TransferInvitationService(source.sql, resolver, sourceBase)
      .issue(userGrant, privateKey);
    const preparedTarget = new PreparedMigrationTarget(target.sql, targetEncryption, targetBase);
    const receiver = new TransferInvitationReceiver(target.sql, resolver, preparedTarget);
    addressReservation = new TransferAddressReservation(target.sql, resolver, preparedTarget);
    sourceRoutes = new Hono();
    registerTransferRoutes(sourceRoutes, new TransferInvitationReceiver(source.sql, resolver,
      new PreparedMigrationTarget(source.sql, encryption, sourceBase)), undefined, fenceService);
    targetPublisher = new TransferFinalRequestPublisher(target.sql, resolver, preparedTarget,
      async (request) => sourceRoutes.fetch(request),
      (url) => { if (url.href !== `${sourceBase}/transfers/requests`) throw new Error("Wrong source origin"); });
    destinationRoutes = new Hono();
    registerTransferRoutes(destinationRoutes, receiver, addressReservation, undefined, targetPublisher);
    originDelivery = new TransferInvitationDelivery(source.sql, resolver, sourceBase,
      async (request) => destinationRoutes.fetch(request),
      (url) => { if (url.href !== "https://target.example.com/.well-known/hail/transfers/invitations")
        throw new Error("Wrong target origin"); });
    signedOffer = await originDelivery.deliver(did);
    const requestRecord = decodeDeterministic(signedOffer.payloadBytes) as unknown as {
      transfer_id: string; destination_rotation_key: string; destination_messaging_key: string };
    targetTransferId = requestRecord.transfer_id;
    destinationRotationPublicKey = requestRecord.destination_rotation_key;
    destinationMessagingPublicKey = requestRecord.destination_messaging_key;
    const profile: HailSenderProfile = {
      type: "hail.sender-profile", version: 1, did, revision: 1,
      display_name: "Transfer Fixture", offers_uncategorized: false,
      categories: [{ id: "updates", label: "Updates" }], updated_at: now,
      key_id: `${did}#hail-messaging`,
    };
    const profileCose = await signPayload("hail.sender-profile", profile,
      createWebCryptoSigner(profile.key_id, privateKey));
    await new OnboardingRepository(source.sql).insertSenderProfile({
      id: randomUUID(), accountId: id, did, revision: 1, payload: profile,
      cose: profileCose, digest: new Uint8Array(createHash("sha256").update(profileCose).digest()),
      signingPublicKey: key.publicKey, updatedAt: now, createdAt: new Date(),
    }, 0);
    const envelope: HailEnvelope = { type: "hail.envelope", version: 1,
      message_id: messageId, from: did, to: remoteDid,
      authorization: { type: "grant", grant_id: grantId }, category: "updates",
      created_at: now, expires_at: now + 3600,
      body: { digest: { algorithm: "sha-256", value: body.digest }, size: body.bytes.length,
        media_type: "application/hail-body+cbor", profile: "spt-1", available_until: now + 31 * 86400,
        access: { type: "bearer", token: randomBytes(32), expires_at: now + 31 * 86400 } },
      reply: { allowed: true, until: now + 86400 },
    };
    replyableEnvelope = await signPayload("hail.envelope", envelope,
      createWebCryptoSigner(`${did}#hail-messaging`, privateKey));
    await new EnvelopeRepository(source.sql).createSent(envelope, replyableEnvelope, id);
    const remoteKey = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    remotePrivateKey = remoteKey.privateKey;
    const receivedMessageId = uuidV7();
    const receivedPayload: HailEnvelope = { ...envelope, from: remoteDid, to: did,
      message_id: receivedMessageId, reply: { allowed: false } };
    incoming = receivedPayload;
    const receivedCose = await signPayload("hail.envelope", receivedPayload,
      createWebCryptoSigner(`${remoteDid}#hail-messaging`, remoteKey.privateKey));
    const receivedDigest = createHash("sha256").update(inspectSignedPayload("hail.envelope", receivedCose).payloadBytes).digest();
    await source.sql`
      INSERT INTO received_envelopes (sender_did, message_id, recipient_did, grant_id,
        authorization_type, local_account_id, envelope_cose, envelope_digest, payload_digest,
        signing_public_key, signing_plc_document, signing_plc_data, signing_plc_operation_log,
        outcome, accepted_at)
      VALUES (${remoteDid}, ${receivedMessageId}, ${did}, ${grantId}, 'grant', ${id},
        ${receivedCose}, ${receivedDigest}, ${receivedDigest}, 'fixture',
        '{}'::jsonb, '{}'::jsonb, '[]'::jsonb, 'accepted', now())
    `;
    await source.sql`INSERT INTO delivery_work (sender_did, message_id)
      VALUES (${remoteDid}, ${receivedMessageId})`;
    const terminalPayload: HailEnvelope = { ...receivedPayload, message_id: terminalMessageId };
    const terminalRepresentation = await signPayload("hail.envelope", terminalPayload,
      createWebCryptoSigner(`${remoteDid}#hail-messaging`, remoteKey.privateKey));
    const terminalDigest = createHash("sha256").update(inspectSignedPayload("hail.envelope", terminalRepresentation).payloadBytes).digest();
    await source.sql`
      INSERT INTO received_envelopes (sender_did, message_id, recipient_did, grant_id,
        authorization_type, local_account_id, envelope_cose, envelope_digest, payload_digest,
        signing_public_key, signing_plc_document, signing_plc_data, signing_plc_operation_log,
        outcome, accepted_at)
      VALUES (${remoteDid}, ${terminalMessageId}, ${did}, ${grantId}, 'grant', ${id},
        ${terminalRepresentation}, ${terminalDigest}, ${terminalDigest}, 'fixture',
        '{}'::jsonb, '{}'::jsonb, '[]'::jsonb, 'accepted', now())
    `;
    await source.sql`INSERT INTO delivery_work (sender_did, message_id, state, reason, status_revision)
      VALUES (${remoteDid}, ${terminalMessageId}, 'failed', 'delivery-expired', 2)`;
    await source.sql`INSERT INTO terminal_status_publications (sender_did, message_id)
      VALUES (${remoteDid}, ${terminalMessageId})`;
    terminalCose = await signPayload("hail.delivery-status", {
      type: "hail.delivery-status", version: 1, message_id: terminalMessageId,
      envelope_digest: { algorithm: "sha-256", value: terminalDigest },
      from: did, to: remoteDid, revision: 2, state: "failed", reason: "delivery-expired",
      occurred_at: now,
    }, createWebCryptoSigner(`${did}#hail-messaging`, privateKey));
  });

  afterAll(async () => {
    if (source) await source.close();
    if (target) await target.close();
  });

  it("rejects an unauthenticated destination request before fencing", async () => {
    const forged = { payloadBytes: signedOffer.payloadBytes,
      signature: Uint8Array.from(signedOffer.signature) };
    forged.signature[0]! ^= 1;
    await expect(fenceService.begin(forged, forged, forged)).rejects.toThrow();
    expect(await fenceService.get(did)).toBeNull();
  });

  it("does not replace the stored user grant with a provider-signed authorization", async () => {
    const payload: TransferGrant = { type: "hail.transfer-grant", version: 1, did,
      nonce: randomUUID(), source_service_base: sourceBase, destination_service_base: targetBase,
      destination_domain: "target.example.com",
      issued_at: Math.floor(Date.now() / 1000), expires_at: Math.floor(Date.now() / 1000) + 300 };
    const providerKey = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    const forgery = await signHandshake(payload, providerKey.privateKey);
    await expect(new TransferInvitationService(source.sql, resolver, sourceBase)
      .issue(forgery, providerKey.privateKey)).rejects.toThrow("signature is invalid");
    expect(await fenceService.get(did)).toBeNull();
  });

  it("accepts the exact user grant over the source endpoint and returns the same Offer on retry", async () => {
    const submit = new TransferGrantSubmission(source.sql, resolver, sourceBase,
      new OnboardingRepository(source.sql), encryption,
      new TransferInvitationService(source.sql, resolver, sourceBase), originDelivery);
    const submissionRoutes = new Hono();
    registerTransferRoutes(submissionRoutes, new TransferInvitationReceiver(source.sql, resolver,
      new PreparedMigrationTarget(source.sql, encryption, sourceBase)), undefined, undefined,
    undefined, submit);
    const { requestWire, parseRequestWire } = await import("../src/migration/wire.js");
    const send = () => submissionRoutes.request("https://source.example.com/hail/transfers/grants",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(requestWire(userGrant)) });
    const first = await send();
    expect(first.status).toBe(200);
    expect(parseRequestWire(new Uint8Array(await first.arrayBuffer()))).toEqual(signedOffer);
    const second = await send();
    expect(second.status).toBe(200);
    expect(parseRequestWire(new Uint8Array(await second.arrayBuffer()))).toEqual(signedOffer);
    const rows = await source.sql`SELECT nonce FROM provider_transfer_authorizations WHERE did = ${did}`;
    expect(rows).toHaveLength(1);
  });

  it("requires the signed request to be observed at the authorized HTTPS origin", async () => {
    await source.sql`UPDATE provider_transfer_authorizations
      SET origin_request_bytes = NULL, origin_request_signature = NULL, origin_confirmed_at = NULL
      WHERE did = ${did}`;
    try {
      await expect(fenceService.begin(signedOffer, signedOffer, signedOffer)).rejects.toThrow("authenticated destination-origin");
      const pendingSubmission = new TransferGrantSubmission(source.sql, resolver, sourceBase,
        new OnboardingRepository(source.sql), encryption,
        new TransferInvitationService(source.sql, resolver, sourceBase),
        { async deliver() { throw new Error("Destination connection unavailable"); } });
      const pendingRoutes = new Hono();
      registerTransferRoutes(pendingRoutes, new TransferInvitationReceiver(source.sql, resolver,
        new PreparedMigrationTarget(source.sql, encryption, sourceBase)), undefined, undefined,
      undefined, pendingSubmission);
      const { requestWire } = await import("../src/migration/wire.js");
      const pendingResponse = await pendingRoutes.request("https://source.example.com/hail/transfers/grants",
        { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
          body: Uint8Array.from(requestWire(userGrant)) });
      expect(pendingResponse.status).toBe(202);
      const badRedirect = new TransferInvitationDelivery(source.sql, resolver, sourceBase,
        async () => new Response(null, { status: 307, headers: { Location: "https://other.example.com" } }),
        (url) => { expect(url.href).toBe("https://target.example.com/.well-known/hail/transfers/invitations"); });
      await expect(badRedirect.deliver(did)).rejects.toThrow("did not acknowledge");
      const oversized = new TransferInvitationDelivery(source.sql, resolver, sourceBase,
        async () => new Response("x".repeat(20_000), { status: 200,
          headers: { "Content-Type": TRANSFER_MEDIA_TYPE } }),
        (url) => { expect(url.href).toBe("https://target.example.com/.well-known/hail/transfers/invitations"); });
      await expect(oversized.deliver(did)).rejects.toThrow("exceeds limit");
      const ambiguous = new TransferInvitationDelivery(source.sql, resolver, sourceBase,
        async (request) => {
          const received = await destinationRoutes.fetch(request);
          expect(received.status).toBe(200);
          throw new Error("Connection lost after destination preparation");
        }, (url) => { expect(url.href).toBe("https://target.example.com/.well-known/hail/transfers/invitations"); });
      await expect(ambiguous.deliver(did)).rejects.toThrow("Connection lost");
      const failedWorker = new TransferDeliveryWorker(source.sql,
        { async deliver() { throw new Error("Destination temporarily unavailable"); } },
        { async publish() {} });
      expect(await failedWorker.runOnce()).toBe("invitation");
      const attempts = await source.sql<{ invitation_attempts: number; invitation_lease_token: string | null }[]>`
        SELECT invitation_attempts, invitation_lease_token FROM provider_transfer_authorizations WHERE did = ${did}`;
      expect(attempts[0]?.invitation_attempts).toBe(1);
      expect(attempts[0]?.invitation_lease_token).toBeNull();
      await source.sql`UPDATE provider_transfer_authorizations SET next_invitation_attempt_at = clock_timestamp()
        WHERE did = ${did}`;
      const restartedWorker = new TransferDeliveryWorker(source.sql, originDelivery,
        { async publish() {} });
      expect(await restartedWorker.runOnce()).toBe("invitation");
      const rows = await source.sql<{ origin_confirmed_at: Date | null }[]>`
        SELECT origin_confirmed_at FROM provider_transfer_authorizations WHERE did = ${did}`;
      expect(rows).toHaveLength(1);
      expect(rows[0]?.origin_confirmed_at).toBeInstanceOf(Date);
    } finally {
      expect(await originDelivery.deliver(did)).toEqual(signedOffer);
      expect(await target.sql`SELECT transfer_id FROM prepared_migration_target_keys WHERE did = ${did}`)
        .toHaveLength(1);
    }
  });

  it("returns the exact signed destination acceptance on retry and rejects forged invitations", async () => {
    const body = invitationWire(userGrant, invitation);
    const repeat = await destinationRoutes.request("https://target.example.com/.well-known/hail/transfers/invitations",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE }, body: Uint8Array.from(body) });
    expect(repeat.status).toBe(200);
    const { parseRequestWire } = await import("../src/migration/wire.js");
    expect(parseRequestWire(new Uint8Array(await repeat.arrayBuffer()))).toEqual(signedOffer);
    const keys = await target.sql`SELECT transfer_id FROM prepared_migration_target_keys WHERE did = ${did}`;
    expect(keys).toHaveLength(1);
    const forgedInvitation = { payloadBytes: invitation.payloadBytes,
      signature: Uint8Array.from(invitation.signature) };
    forgedInvitation.signature[0]! ^= 1;
    const rejected = await destinationRoutes.request("https://target.example.com/.well-known/hail/transfers/invitations",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(invitationWire(userGrant, forgedInvitation)) });
    expect(rejected.status).toBe(400);
    expect(await target.sql`SELECT transfer_id FROM prepared_migration_target_keys WHERE did = ${did}`)
      .toHaveLength(1);
  });

  it("fails closed on an invitation destination mismatch or expired grant", async () => {
    try {
      await source.sql`UPDATE provider_transfer_authorizations
        SET destination_service_base = 'https://other.example.com/hail' WHERE did = ${did}`;
      await expect(originDelivery.deliver(did)).rejects.toThrow("does not match the current user grant");
      await source.sql`UPDATE provider_transfer_authorizations
        SET destination_service_base = ${targetBase}, expires_at = now() - interval '1 second' WHERE did = ${did}`;
      await expect(fenceService.begin(signedOffer, signedOffer, signedOffer))
        .rejects.toThrow("No valid user-authorized invitation");
    } finally {
      const original = await source.sql<{ grant_bytes: Uint8Array }[]>`
        SELECT grant_bytes FROM provider_transfer_authorizations WHERE did = ${did}`;
      const { decodeDeterministic } = await import("@hailproto/codec");
      const grant = decodeDeterministic(original[0]!.grant_bytes) as unknown as TransferGrant;
      await source.sql`UPDATE provider_transfer_authorizations
        SET destination_service_base = ${targetBase}, expires_at = to_timestamp(${grant.expires_at})
        WHERE did = ${did}`;
    }
    expect(await fenceService.get(did)).toBeNull();
  });

  it("authenticates address selection directly at the new provider and atomically reserves its domain", async () => {
    const grant = decodeDeterministic(userGrant.payloadBytes) as unknown as TransferGrant;
    const now = Math.floor(Date.now() / 1000);
    const selected: TransferAddressSelection = {
      type: "hail.transfer-address-selection", version: 1, did, nonce: grant.nonce,
      transfer_id: targetTransferId, grant_digest: handshakeDigest(userGrant.payloadBytes),
      offer_digest: handshakeDigest(signedOffer.payloadBytes), address: selectedAddress,
      selection_nonce: randomUUID(), issued_at: now, expires_at: now + 1800,
    };
    const forgedKey = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    const forged = await signHandshake(selected, forgedKey.privateKey);
    await expect(addressReservation.reserve(forged)).rejects.toThrow("signature is invalid");
    const rotatedBytes = new Uint8Array(34);
    rotatedBytes.set([0xed, 0x01]);
    rotatedBytes.set(new Uint8Array(await crypto.subtle.exportKey("raw", forgedKey.publicKey)), 2);
    const rotatedIdentity = `did:key:${base58btc.encode(rotatedBytes)}`;
    const rotatedResolver: HailDidResolver = { async resolve(value) {
      return { ...(await resolver.resolve(value)), identityDidKey: rotatedIdentity };
    } };
    const rotatedSelection = await signHandshake(selected, forgedKey.privateKey);
    await expect(new TransferAddressReservation(target.sql, rotatedResolver,
      new PreparedMigrationTarget(target.sql, targetEncryption, targetBase))
      .reserve(rotatedSelection)).rejects.toThrow("signature is invalid");
    const wrongDomain = await signHandshake({ ...selected, address: "alice@other.example.com" }, identityPrivateKey);
    await expect(addressReservation.reserve(wrongDomain)).rejects.toThrow("not for this provider");
    const occupiedId = randomUUID();
    await target.sql`INSERT INTO provider_accounts (id, tenant_id, canonical_address, onboarding_state)
      VALUES (${occupiedId}, ${randomUUID()}, ${selectedAddress}, 'reserved')`;
    signedSelection = await signHandshake(selected, identityPrivateKey);
    try { await expect(addressReservation.reserve(signedSelection)).rejects.toThrow("Address not available"); }
    finally { await target.sql`DELETE FROM provider_accounts WHERE id = ${occupiedId}`; }
    const competingSelection = await signHandshake({ ...selected, selection_nonce: randomUUID() }, identityPrivateKey);
    const race = await Promise.allSettled([
      addressReservation.reserve(signedSelection), addressReservation.reserve(competingSelection),
    ]);
    expect(race.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(race.filter((result) => result.status === "rejected")).toHaveLength(1);
    if (race[1]?.status === "fulfilled") signedSelection = competingSelection;
    const clientFacingRoutes = new Hono();
    const ambiguousPublisher = { async publish() {
      throw new Error("Target-to-source response temporarily ambiguous");
    } };
    registerTransferRoutes(clientFacingRoutes, new TransferInvitationReceiver(target.sql, resolver,
      new PreparedMigrationTarget(target.sql, targetEncryption, targetBase)),
    addressReservation, undefined, ambiguousPublisher);
    const { requestWire, parseRequestWire } = await import("../src/migration/wire.js");
    const chosen = await clientFacingRoutes.request("https://target.example.com/.well-known/hail/transfers/reservations",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(requestWire(signedSelection)) });
    expect(chosen.status).toBe(202);
    signedReservation = parseRequestWire(new Uint8Array(await chosen.arrayBuffer()));
    const reserved = await addressReservation.reserve(signedSelection);
    expect(reserved.receipt).toEqual(signedReservation);
    expect((await addressReservation.reserve(signedSelection)).receipt).toEqual(signedReservation);
    await expect(new OnboardingRepository(target.sql).reserve(selectedAddress))
      .rejects.toThrow("held for a provider transfer");
    expect(await fenceService.get(did)).toBeNull();
    expect(await target.sql`SELECT transfer_id FROM transfer_address_reservations
      WHERE canonical_address = ${selectedAddress}`).toHaveLength(1);
  });

  it("lets a committed writer win before the exclusive account-row fence", async () => {
    const work = new DeliveryRepository(source.sql);
    claimedDelivery = (await work.claimDue())!;
    expect(claimedDelivery.messageId).toBe(incoming.message_id);
    const publicationResolver: HailDidResolver = { resolve: (value) => value === did
      ? resolver.resolve(value)
      : Promise.resolve({ did: remoteDid, identityDidKey: "fixture", messagingDidKey: "fixture",
        serviceBase: "https://remote.example.com/hail", evidence: { document: {}, data: {}, log: [] } }) };
    let releaseResponse!: () => void;
    let requestStarted!: () => void;
    const responseWait = new Promise<void>((resolve) => { releaseResponse = resolve; });
    const reachedFetch = new Promise<void>((resolve) => { requestStarted = resolve; });
    const publisher = new TerminalStatusPublisher(source.sql, { signCurrent: async () => terminalCose },
      publicationResolver, async () => {
        requestStarted();
        await responseWait;
        return new Response(null, { status: 204 });
      }, async () => {});
    const inFlightPublication = publisher.publishOne();
    await reachedFetch;
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const locked = new Promise<void>((resolve) => { entered = resolve; });
    const writer = source.sql.begin(async (tx) => {
      await tx`SELECT id FROM provider_accounts WHERE id = ${id} FOR UPDATE`;
      entered();
      await held;
      await tx`UPDATE provider_accounts SET state_version = state_version + 1 WHERE id = ${id}`;
    });
    await locked;
    let fenced = false;
    const pending = targetPublisher.publish(targetTransferId)
      .then(async () => { fenced = true; return fenceService.get(did); });
    await new Promise((resolve) => setTimeout(resolve, 35));
    expect(fenced).toBe(false);
    release();
    await writer;
    const fence = await pending;
    expect(fence?.state).toBe("fenced");
    const final = await target.sql<{ final_request_bytes: Uint8Array;
      final_request_signature: Uint8Array }[]>`
        SELECT final_request_bytes, final_request_signature FROM received_transfer_invitations
        WHERE transfer_id = ${targetTransferId}`;
    signedRequest = { payloadBytes: final[0]!.final_request_bytes,
      signature: final[0]!.final_request_signature };
    expect(await fenceService.previouslyAccepted(signedRequest, signedSelection, signedReservation)).toBe(true);
    releaseResponse();
    await expect(inFlightPublication).rejects.toThrow("migration-fenced");
    const account = await source.sql<{ state_version: number }[]>`
      SELECT state_version FROM provider_accounts WHERE id = ${id}`;
    expect(account[0]?.state_version).toBe(2);
  });

  it("acknowledges an exact final-request retry without another fence or address change", async () => {
    const fencedBefore = await source.sql<{ state: string; transfer_id: string }[]>`
      SELECT state, transfer_id FROM provider_migration_fences WHERE did = ${did}`;
    await expect(targetPublisher.publish(targetTransferId)).resolves.toBeUndefined();
    const fencedAfter = await source.sql<{ state: string; transfer_id: string }[]>`
      SELECT state, transfer_id FROM provider_migration_fences WHERE did = ${did}`;
    expect(fencedAfter).toHaveLength(1);
    expect(fencedAfter[0]).toMatchObject({ state: fencedBefore[0]!.state,
      transfer_id: fencedBefore[0]!.transfer_id });
    const changedSelection = await signHandshake({
      ...(decodeDeterministic(signedSelection.payloadBytes) as unknown as TransferAddressSelection),
      address: "other@target.example.com", selection_nonce: randomUUID(),
    }, identityPrivateKey);
    const { finalRequestWire } = await import("../src/migration/wire.js");
    const rejected = await sourceRoutes.request("https://source.example.com/hail/transfers/requests",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(finalRequestWire(changedSelection, signedReservation, signedRequest)) });
    expect(rejected.status).toBe(400);
    expect(await fenceService.previouslyAccepted(signedRequest, changedSelection, signedReservation)).toBe(false);
    const forgedReceipt = { payloadBytes: signedReservation.payloadBytes,
      signature: Uint8Array.from(signedReservation.signature) };
    forgedReceipt.signature[0]! ^= 1;
    const rejectedReceipt = await sourceRoutes.request("https://source.example.com/hail/transfers/requests",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(finalRequestWire(signedSelection, forgedReceipt, signedRequest)) });
    expect(rejectedReceipt.status).toBe(400);
  });

  it("blocks admissions, Grant changes, reply claims and worker/publication writes after the fence", async () => {
    const fence = await fenceService.get(did);
    expect(fence?.state).toBe("fenced");
    const expectFenced = async (request: Promise<unknown>) => expect(request).rejects.toThrow("migration-fenced");
    await expectFenced(source.sql`UPDATE grant_lineages SET current_status = 'revoked' WHERE grant_id = ${grantId}`);
    await expectFenced(source.sql`UPDATE reply_capabilities SET reply_until = reply_until + 1
      WHERE original_sender_did = ${did} AND original_message_id = ${messageId}`);
    await expectFenced(source.sql`UPDATE grant_publications SET next_attempt_at = now()
      WHERE grant_id = ${grantId}`);
    await expectFenced(source.sql`UPDATE body_authorizations SET expires_at = expires_at + 1
      WHERE sender_account_id = ${id}`);
    const outgoing = inspectSignedPayload("hail.envelope", replyableEnvelope).payload;
    const tokenHash = createHash("sha256").update(outgoing.body.access.token).digest();
    expect(await new BodyRepository(source.sql).retrieve(outgoing.body.digest.value, tokenHash,
      Math.floor(Date.now() / 1000))).toBe("missing-body");
    expect(await new GrantRepository(source.sql).claimDuePublication(30_000)).toBeNull();
    expect(await new DeliveryRepository(source.sql).claimDue()).toBeNull();
    expect(await new OnboardingRepository(source.sql).findCurrentByDid(did)).toBeNull();
    const newPayload: HailEnvelope = { ...incoming, message_id: uuidV7() };
    const representation = await signPayload("hail.envelope", newPayload,
      createWebCryptoSigner(`${remoteDid}#hail-messaging`, remotePrivateKey));
    const payloadDigest = createHash("sha256").update(inspectSignedPayload("hail.envelope", representation).payloadBytes).digest();
    await expectFenced(new EnvelopeRepository(source.sql).accept({ payload: newPayload, representation,
      envelopeDigest: payloadDigest, payloadDigest, localAccountId: id,
      signingPublicKey: "fixture", evidence: { document: {}, data: {}, log: [] },
      now: Math.floor(Date.now() / 1000) }));
    const reservation = await source.sql`SELECT message_id FROM received_envelopes
      WHERE sender_did = ${remoteDid} AND message_id = ${newPayload.message_id}`;
    expect(reservation).toHaveLength(0);
    const nextGrant: HailGrant = { ...initialGrant, revision: 2,
      previous: new Uint8Array(initialGrantDigest), status: "revoked", updated_at: initialGrant.updated_at + 1 };
    const grantRepresentation = await signPayload("hail.grant", nextGrant,
      createWebCryptoSigner(`${did}#hail-identity`, identityPrivateKey));
    await expectFenced(new GrantRepository(source.sql).appendAuthoritativeRevocation({
      revision: { payload: nextGrant, representation: grantRepresentation,
        digest: new Uint8Array(createHash("sha256").update(grantRepresentation).digest()),
        signingPublicKey: "fixture", signingPlcEvidence: { document: {}, data: {}, log: [] },
        localAccountId: id, localRole: "grantor" },
      expectedCurrentRevision: 1, expectedCurrentDigest: initialGrantDigest,
    }));
    await expectFenced(new DeliveryRepository(source.sql).deliver(claimedDelivery, bodyBytes));
    const signer = new DeliveryStatusSigner(source.sql, new OnboardingRepository(source.sql),
      encryption, resolver, sourceBase);
    await expectFenced(signer.signCurrent(remoteDid, terminalMessageId));
    const statusPublisher = new TerminalStatusPublisher(source.sql,
      { signCurrent: async () => terminalCose }, resolver,
      async () => new Response(null, { status: 204 }), async () => {});
    expect(await statusPublisher.publishOne()).toBe("idle");
    await expect(fenceService.releaseBeforeExport(did, randomUUID())).rejects.toThrow("matching");
  });

  it("refuses to redirect an authorized request to a different custodial source", async () => {
    const custodialDid = `did:plc:${"c".repeat(24)}`;
    const custodialId = randomUUID();
    await source.sql`
      INSERT INTO provider_accounts (id, tenant_id, canonical_address, did, onboarding_state,
        activated_at, activation_binding_digest, activation_verification_mode)
      VALUES (${custodialId}, ${randomUUID()}, ${`custodial-${custodialId}@example.com`},
        ${custodialDid}, 'active', now(), ${randomBytes(32)}, 'public')
    `;
    const bogusResolver: HailDidResolver = { async resolve() {
      return { did: custodialDid, identityDidKey: userIdentityPublicKey,
        messagingDidKey: destinationMessagingPublicKey, serviceBase: sourceBase,
        evidence: { document: {}, data: { rotationKeys: [userRecoveryPublicKey] }, log: [] } };
    } };
    try {
      await expect(new MigrationFenceService(source.sql, bogusResolver, sourceBase)
        .begin(signedRequest, signedSelection, signedReservation))
        .rejects.toThrow("Current PLC state");
      expect(await source.sql`SELECT did FROM provider_migration_fences WHERE did = ${custodialDid}`).toHaveLength(0);
    } finally {
      await source.sql`DELETE FROM provider_accounts WHERE id = ${custodialId}`;
    }
  });

  it("exports an immutable signed complete-domain snapshot and stages only an inert authenticated import", async () => {
    const fence = (await fenceService.get(did))!;
    const snapshot = await transferSource.exportFenced(fence);
    const again = await transferSource.exportFenced(fence);
    expect(again.bytes).toEqual(snapshot.bytes);
    expect(again.signature).toEqual(snapshot.signature);
    const signedCutover = await signOperation({
      type: "plc_operation", rotationKeys: [userRecoveryPublicKey, destinationRotationPublicKey],
      verificationMethods: { "hail-identity": userIdentityPublicKey,
        "hail-messaging": destinationMessagingPublicKey },
      alsoKnownAs: [], services: { hail: { type: "HailMessaging", endpoint: targetBase } },
      prev: (await cidForCbor(genesisOperation)).toString(),
    }, userRecoveryPrivateKey);
    signedCutoverOperation = signedCutover;
    const operationBytes = new TextEncoder().encode(JSON.stringify(signedCutover));
    const operationDigest = new Uint8Array(createHash("sha256").update(dagCbor.encode(signedCutover)).digest());
    const createdAt = Math.floor(Date.now() / 1000);
    const binding: HailAddressBinding = { type: "hail.address-binding", version: 1,
      address: selectedAddress, did, issued_at: createdAt,
      expires_at: createdAt + 90 * 86400, key_id: `${did}#hail-identity` };
    destinationBinding = await signPayload("hail.address-binding", binding,
      createWebCryptoSigner(binding.key_id, identityPrivateKey));
    const consent: SignedPortableConsent = await signPortableMigrationConsent({
      type: "hail.portable-migration-consent", version: 1, did, transfer_id: fence.transferId,
      snapshot_digest: snapshot.digest, plc_operation_sha256: operationDigest,
      source_service_base: sourceBase,
      destination_service_base: targetBase, destination_address: binding.address,
      destination_rotation_key: destinationRotationPublicKey,
      destination_messaging_key: destinationMessagingPublicKey, user_recovery_key: userRecoveryPublicKey,
      user_identity_key: userIdentityPublicKey, created_at: createdAt, expires_at: createdAt + 3600,
    }, identityPrivateKey);
    const manifest = await transferTarget.stageImport(snapshot, consent, operationBytes, destinationBinding);
    expect(manifest.did).toBe(did);
    expect(manifest.custodyProfile).toBe("portable");
    expect(manifest.tables.account_keys).toHaveLength(2);
    expect(manifest.tables.portable_custody_evidence).toHaveLength(1);
    expect(manifest.tables.account_keys.every((key) => !Object.hasOwn(key, "encrypted_private_key"))).toBe(true);
    await new PreparedMigrationTarget(target.sql, targetEncryption, targetBase).assertOwnership({
      transferId: targetTransferId, did, destinationServiceBase: targetBase,
      rotationPublicKey: destinationRotationPublicKey, messagingPublicKey: destinationMessagingPublicKey,
    });
    const preparedRow = await target.sql<{ state: string }[]>`
      SELECT state FROM prepared_migration_target_keys WHERE transfer_id = ${targetTransferId}`;
    expect(preparedRow[0]?.state).toBe("staged");
    expect(manifest.tables.sender_profiles).toHaveLength(1);
    expect(manifest.tables.sent_envelopes).toHaveLength(1);
    expect(manifest.tables.reply_capabilities).toHaveLength(1);
    const { sig: _userSignature, ...unsignedCutover } = signedCutover;
    const lowerPriorityOperation = await signOperation(unsignedCutover, sourceProviderRotationKey);
    await expect(transferTarget.stageImport(snapshot, consent,
      new TextEncoder().encode(JSON.stringify(lowerPriorityOperation)), destinationBinding))
      .rejects.toThrow();
    expect(await transferTarget.stageImport(snapshot, consent, operationBytes, destinationBinding)).toEqual(manifest);
    const account = await target.sql`SELECT id FROM provider_accounts WHERE did = ${did}`;
    expect(account).toHaveLength(0);
    const imported = await target.sql<{ state: string }[]>`
      SELECT state FROM pending_migration_imports WHERE transfer_id = ${fence.transferId}`;
    expect(imported[0]?.state).toBe("staged");
    const changed: SignedTransferSnapshot = { ...snapshot, signature: Uint8Array.from(snapshot.signature) };
    changed.signature[0] = changed.signature[0]! ^ 1;
    await expect(transferTarget.stageImport(changed, consent, operationBytes, destinationBinding))
      .rejects.toThrow("signature is invalid");
    const changedConsent: SignedPortableConsent = { ...consent, signature: Uint8Array.from(consent.signature) };
    changedConsent.signature[0] = changedConsent.signature[0]! ^ 1;
    await expect(transferTarget.stageImport(snapshot, changedConsent, operationBytes, destinationBinding))
      .rejects.toThrow("consent signature is invalid");
    const forgedDestination = await signPortableMigrationConsent({
      type: "hail.portable-migration-consent", version: 1, did, transfer_id: fence.transferId,
      snapshot_digest: snapshot.digest, plc_operation_sha256: operationDigest,
      source_service_base: sourceBase,
      destination_service_base: targetBase, destination_address: binding.address,
      destination_rotation_key: destinationRotationPublicKey,
      destination_messaging_key: (await resolver.resolve(did)).messagingDidKey,
      user_recovery_key: userRecoveryPublicKey,
      user_identity_key: userIdentityPublicKey, created_at: createdAt, expires_at: createdAt + 3600,
    }, identityPrivateKey);
    await expect(transferTarget.stageImport(snapshot, forgedDestination, operationBytes, destinationBinding))
      .rejects.toThrow("does not match the exact snapshot");
    const invalidBinding = Uint8Array.from(destinationBinding);
    invalidBinding[invalidBinding.length - 1] = invalidBinding[invalidBinding.length - 1]! ^ 1;
    await expect(transferTarget.stageImport(snapshot, consent, operationBytes, invalidBinding))
      .rejects.toThrow();
    const truncated = JSON.parse(new TextDecoder().decode(snapshot.bytes)) as {
      tables: { sent_envelopes: unknown[] };
    };
    truncated.tables.sent_envelopes = [];
    const truncatedBytes = new TextEncoder().encode(JSON.stringify(truncated));
    await expect(transferTarget.stageImport({ ...snapshot, bytes: truncatedBytes,
      digest: new Uint8Array(createHash("sha256").update(truncatedBytes).digest()) }, consent,
      operationBytes, destinationBinding))
      .rejects.toThrow("reply invitation lacks its signed original");
    const intact = await target.sql<{ state: string }[]>`
      SELECT state FROM pending_migration_imports WHERE transfer_id = ${fence.transferId}`;
    expect(intact[0]?.state).toBe("staged");
    await expect(fenceService.releaseBeforeExport(did, fence.transferId)).rejects.toThrow("unexported");
  });

  it("labels a private PLC cutover without treating the single reader as independent", async () => {
    const fence = (await fenceService.get(did))!;
    const rows = await target.sql<{ manifest_bytes: Uint8Array }[]>`
      SELECT manifest_bytes FROM pending_migration_imports WHERE transfer_id = ${fence.transferId}`;
    const original = new Uint8Array(rows[0]!.manifest_bytes);
    const manifest = JSON.parse(new TextDecoder().decode(original)) as {
      tables: { portable_custody_evidence: { monitor_verification_mode: string }[] } };
    manifest.tables.portable_custody_evidence[0]!.monitor_verification_mode = "poc-local";
    const pocManifest = new TextEncoder().encode(JSON.stringify(manifest));
    const updated = signedCutoverOperation;
    const result = await validateOperationLog(did, [genesisOperation, updated]);
    const cid = (await cidForCbor(updated)).toString();
    const observer: IndependentPlcObserver = { origin: "http://plc.fixture:2582",
      resolver: { async resolve() { return { did, identityDidKey: userIdentityPublicKey,
        messagingDidKey: destinationMessagingPublicKey, serviceBase: targetBase,
        evidence: { document: {}, data: result!, log: [genesisOperation, updated] } }; } },
      async audit() { return [{ did, operation: updated, cid,
        nullified: false, createdAt: new Date().toISOString() }]; },
    };
    expect(() => new PrivatePocCutoverGate(target.sql, observer,
      "https://plc.directory", targetBase)).toThrow("pinned internal PLC");
    try {
      await target.sql`UPDATE pending_migration_imports SET manifest_bytes = ${pocManifest}
        WHERE transfer_id = ${fence.transferId}`;
      const pocGate = new PrivatePocCutoverGate(target.sql, observer,
        "http://plc.fixture:2582", targetBase);
      expect((await pocGate.assess(fence.transferId)).eligible).toBe(true);
      const assessment = await target.sql<{ assessment_profile: string; mirror_origins: string | string[] }[]>`
        SELECT assessment_profile, mirror_origins FROM portable_cutover_observations
        WHERE transfer_id = ${fence.transferId}`;
      expect(assessment[0]?.assessment_profile).toBe("private-poc");
      expect(typeof assessment[0]?.mirror_origins === "string" ?
        JSON.parse(assessment[0].mirror_origins) : assessment[0]?.mirror_origins)
        .toEqual(["http://plc.fixture:2582"]);
      const publicGate = new PortableCutoverGate(target.sql, [observer, observer]);
      await expect(publicGate.assess(fence.transferId)).rejects.toThrow("signed independent monitor");
    } finally {
      await target.sql`DELETE FROM portable_cutover_observations WHERE transfer_id = ${fence.transferId}`;
      await target.sql`UPDATE pending_migration_imports SET manifest_bytes = ${original}
        WHERE transfer_id = ${fence.transferId}`;
    }
  });

  it("requires matching independent PLC witnesses and monitor coverage throughout the recovery window", async () => {
    const fence = (await fenceService.get(did))!;
    const updated = signedCutoverOperation;
    const nextState = await validateOperationLog(did, [genesisOperation, updated]);
    expect(nextState).not.toBeNull();
    expect(nextState?.services.hail?.endpoint).toBe(targetBase);
    expect(nextState?.rotationKeys).toEqual([userRecoveryPublicKey, destinationRotationPublicKey]);
    const operationCid = (await cidForCbor(updated)).toString();
    const observed = { did, identityDidKey: userIdentityPublicKey,
      messagingDidKey: destinationMessagingPublicKey, serviceBase: targetBase,
      evidence: { document: {}, data: nextState!, log: [genesisOperation, updated] } };
    const observer = (origin: string): IndependentPlcObserver => ({
      origin,
      resolver: { async resolve() { return observed; } },
      async audit() { return [{ did, operation: updated, cid: operationCid,
        nullified: false, createdAt: new Date().toISOString() }]; },
    });
    const witnesses: [IndependentPlcObserver, IndependentPlcObserver] = [
      observer("https://mirror-one.example.com"), observer("https://mirror-two.example.com"),
    ];
    cutoverClock = Date.now();
    targetGate = new PortableCutoverGate(target.sql, witnesses, () => new Date(cutoverClock));
    const first = Math.floor(cutoverClock / 1000);
    const report = async () => signMonitorAttestation({
      type: "hail.plc-monitor-attestation", version: 1, did,
      transfer_id: fence.transferId, operation_cid: operationCid,
      monitor_origin: "https://monitor.example.com", coverage_since: first - 3600,
      observed_at: Math.floor(cutoverClock / 1000),
    }, monitorPrivateKey);
    const initial = await targetGate.assess(fence.transferId, await report());
    expect(initial.eligible).toBe(true);
    expect(initial.earliestEligibleAt.getTime()).toBe(initial.firstSeenAt.getTime());
    // Independent observations permit immediate activation. A delayed operator
    // still has to fail previously accepted work whose original deadline expired.
    cutoverClock += 2 * 3600 * 1000;
    expect((await targetGate.assess(fence.transferId, await report())).eligible).toBe(true);
    const targetAccount = await target.sql`SELECT id FROM provider_accounts WHERE did = ${did}`;
    expect(targetAccount).toHaveLength(0); // Assessment never activates an import.
    const disagreement = new PortableCutoverGate(target.sql, [witnesses[0], {
      ...witnesses[1], async audit() { return [{ did, operation: updated, cid: "bafyunexpected",
        nullified: false, createdAt: new Date().toISOString() }]; },
    }], () => new Date(cutoverClock));
    await expect(disagreement.assess(fence.transferId, await report())).rejects.toThrow("Mirror audit");
    const badMonitor = await report();
    badMonitor.signature[0] = badMonitor.signature[0]! ^ 1;
    await expect(targetGate.assess(fence.transferId, badMonitor)).rejects.toThrow("signature is invalid");
  });

  it("materializes the entire domain only after finality and external address verification", async () => {
    const fence = (await fenceService.get(did))!;
    const newState = await validateOperationLog(did, [genesisOperation, signedCutoverOperation]);
    expect(newState).not.toBeNull();
    const destinationResolver: HailDidResolver = { async resolve(value) {
      if (value !== did) throw new Error("Unknown DID");
      return { did, identityDidKey: userIdentityPublicKey,
        messagingDidKey: destinationMessagingPublicKey, serviceBase: targetBase,
        evidence: { document: {}, data: newState!, log: [genesisOperation, signedCutoverOperation] } };
    } };
    const signedBinding = inspectSignedPayload("hail.address-binding", destinationBinding).payload;
    const bindingDigest = new Uint8Array(createHash("sha256").update(destinationBinding).digest());
    const verified = { address: signedBinding.address, did,
      serviceBase: targetBase, messagingDidKey: destinationMessagingPublicKey,
      identityDidKey: userIdentityPublicKey, plcEvidence: (await destinationResolver.resolve(did)).evidence,
      verifiedAt: new Date(cutoverClock), binding: signedBinding,
      representation: destinationBinding, digest: bindingDigest };
    let matchAddress = false;
    const addressVerifier = { async verify() { return matchAddress ? verified : {
      ...verified, digest: randomBytes(32),
    }; } };
    const activation = new PortableMigrationActivation(target.sql, targetEncryption, destinationResolver,
      targetGate, addressVerifier, targetBase, "https://plc.directory", () => new Date(cutoverClock));
    const report = async () => signMonitorAttestation({
      type: "hail.plc-monitor-attestation", version: 1, did, transfer_id: fence.transferId,
      operation_cid: (await cidForCbor(signedCutoverOperation)).toString(),
      monitor_origin: "https://monitor.example.com",
      coverage_since: Math.floor(cutoverClock / 1000) - 73 * 3600,
      observed_at: Math.floor(cutoverClock / 1000),
    }, monitorPrivateKey);
    await expect(activation.activate(fence.transferId, await report())).rejects.toThrow("address does not select");
    expect(await target.sql`SELECT id FROM provider_accounts WHERE did = ${did}`).toHaveLength(0);
    matchAddress = true;
    const occupiedId = id;
    await target.sql`INSERT INTO provider_accounts (id, tenant_id, canonical_address, onboarding_state)
      VALUES (${occupiedId}, ${randomUUID()}, ${`conflict-${id}@target.example.com`}, 'reserved')`;
    await expect(activation.activate(fence.transferId, await report())).rejects.toThrow();
    expect(await target.sql`SELECT id FROM provider_accounts WHERE did = ${did}`).toHaveLength(0);
    const pending = await target.sql<{ state: string }[]>`
      SELECT state FROM pending_migration_imports WHERE transfer_id = ${fence.transferId}`;
    expect(pending[0]?.state).toBe("staged");
    await target.sql`DELETE FROM provider_accounts WHERE id = ${occupiedId}`;
    expect(await activation.activate(fence.transferId, await report())).toEqual({ did, accountId: id });
    const account = await target.sql<{ onboarding_state: string; canonical_address: string }[]>`
      SELECT onboarding_state, canonical_address FROM provider_accounts WHERE did = ${did}`;
    expect(account[0]).toMatchObject({ onboarding_state: "active", canonical_address: signedBinding.address });
    const keys = await target.sql<{ role: string; public_key: string }[]>`
      SELECT role, public_key FROM account_keys WHERE account_id = ${id} ORDER BY role`;
    expect(keys.map((entry) => entry.role)).toEqual(["hail-messaging", "plc-rotation"]);
    expect(keys.find((entry) => entry.role === "hail-messaging")?.public_key).toBe(destinationMessagingPublicKey);
    expect(keys.find((entry) => entry.role === "plc-rotation")?.public_key).toBe(destinationRotationPublicKey);
    const currentProfile = await new OnboardingRepository(target.sql).findCurrentByDid(did);
    expect(currentProfile?.revision).toBe(2);
    expect(currentProfile?.signingPublicKey).toBe(destinationMessagingPublicKey);
    const work = await target.sql<{ state: string; lease_token: string | null }[]>`
      SELECT state, lease_token FROM delivery_work WHERE sender_did = ${remoteDid} AND message_id = ${incoming.message_id}`;
    expect(work[0]).toMatchObject({ state: "accepted", lease_token: null });
    const worker = new DeliveryWorker(new DeliveryRepository(target.sql), {
      async retrieve() { throw new Error("An expired accepted envelope must not fetch a body"); },
    }, () => new Date(cutoverClock));
    expect(await worker.processOne()).toBe("failed");
    const failure = await target.sql<{ state: string; reason: string }[]>`
      SELECT state, reason FROM delivery_work WHERE sender_did = ${remoteDid} AND message_id = ${incoming.message_id}`;
    expect(failure[0]).toMatchObject({ state: "failed", reason: "delivery-expired" });
    const signer = new DeliveryStatusSigner(target.sql, new OnboardingRepository(target.sql),
      targetEncryption, destinationResolver, targetBase);
    const terminal = await signer.signCurrent(remoteDid, incoming.message_id);
    expect(inspectSignedPayload("hail.delivery-status", terminal!).payload).toMatchObject({
      from: did, to: remoteDid, state: "failed", revision: 2,
    });
    const receipt = await activation.issueReceipt(fence.transferId);
    const retiredSource = new MigrationFenceService(source.sql, destinationResolver,
      sourceBase, () => new Date(cutoverClock));
    const tamperedReceipt = { ...receipt, signature: Uint8Array.from(receipt.signature) };
    tamperedReceipt.signature[0] = tamperedReceipt.signature[0]! ^ 1;
    await expect(retiredSource.retire(did, fence.transferId, tamperedReceipt)).rejects.toThrow("signature is invalid");
    expect((await fenceService.get(did))?.state).toBe("exported");
    await retiredSource.retire(did, fence.transferId, receipt);
    expect((await fenceService.get(did))?.state).toBe("retired");
    await expect(retiredSource.retire(did, fence.transferId, receipt)).rejects.toThrow("cannot retire");
    await expect(activation.activate(fence.transferId, await report())).rejects.toThrow("staged");
    const outgoing = inspectSignedPayload("hail.envelope", replyableEnvelope).payload;
    const tokenHash = createHash("sha256").update(outgoing.body.access.token).digest();
    expect(await new BodyRepository(source.sql).retrieve(outgoing.body.digest.value, tokenHash,
      Math.floor(cutoverClock / 1000))).toBeNull();
  });
});
