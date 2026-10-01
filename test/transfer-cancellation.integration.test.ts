import { randomBytes, randomUUID } from "node:crypto";
import { P256Keypair } from "@atproto/crypto";
import { didForCreateOp, signOperation } from "@did-plc/lib";
import { decodeDeterministic, encodeBase64Url } from "@hailproto/codec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { ProviderDatabase } from "../src/db/database.js";
import { KeyEncryptor } from "../src/identity/key-encryption.js";
import { generateAccountKeys, importEd25519PrivateKey } from "../src/identity/keys.js";
import { OnboardingRepository } from "../src/onboarding/repository.js";
import { TransferCancellationService } from "../src/migration/cancellation.js";
import { TransferCancellationReceiver } from "../src/migration/cancellation-receiver.js";
import { TransferAddressReservation } from "../src/migration/address-selection.js";
import { MigrationFenceService } from "../src/migration/fence.js";
import { TransferInvitationService, handshakeDigest, signHandshake,
  type SignedHandshake, type TransferAddressSelection, type TransferCancellation,
  type TransferGrant } from "../src/migration/handshake.js";
import { TransferInvitationDelivery } from "../src/migration/invitation-delivery.js";
import { TransferInvitationReceiver } from "../src/migration/invitation-receiver.js";
import { registerTransferRoutes } from "../src/migration/routes.js";
import { cancellationWire, parseRequestWire, requestWire, TRANSFER_MEDIA_TYPE } from "../src/migration/wire.js";
import { PreparedMigrationTarget } from "../src/migration/target-keys.js";
import { TransferFinalRequestPublisher } from "../src/migration/final-request-publisher.js";
import { TransferDeliveryWorker } from "../src/migration/delivery-worker.js";
import type { HailDidResolver } from "../src/plc/resolver.js";

const integration = process.env.DATABASE_URL && process.env.TRANSFER_TARGET_DATABASE_URL ? describe : describe.skip;
const sourceBase = "https://source.example.com/hail";
const targetBase = "https://target.example.com/hail";

integration("user cancellation before ambiguous final handoff", () => {
  let source: ProviderDatabase;
  let target: ProviderDatabase;
  let did: string;
  let resolver: HailDidResolver;
  let userKey: CryptoKey;
  let grant: SignedHandshake;
  let invitation: SignedHandshake;
  let offer: SignedHandshake;
  let transferId: string;
  let sourceKeys: ReturnType<typeof generateAccountKeys> extends Promise<infer T> ? T : never;
  let sourceEncryptor: KeyEncryptor;
  let targetKeys: PreparedMigrationTarget;

  beforeAll(async () => {
    source = new ProviderDatabase(process.env.DATABASE_URL!);
    target = new ProviderDatabase(process.env.TRANSFER_TARGET_DATABASE_URL!);
    await source.migrate();
    await target.migrate();
    const accountId = randomUUID();
    sourceEncryptor = new KeyEncryptor(encodeBase64Url(randomBytes(32)));
    sourceKeys = await generateAccountKeys(accountId, sourceEncryptor);
    userKey = sourceKeys.identityPrivateKey;
    const recovery = await P256Keypair.create({ exportable: true });
    const op = await signOperation({ type: "plc_operation", prev: null,
      rotationKeys: [recovery.did(), sourceKeys.rotationDidKey],
      verificationMethods: { "hail-identity": sourceKeys.identityDidKey,
        "hail-messaging": sourceKeys.messagingDidKey }, alsoKnownAs: [],
      services: { hail: { type: "HailMessaging", endpoint: sourceBase } },
    }, recovery);
    did = await didForCreateOp(op);
    resolver = { async resolve(value) {
      if (value !== did) throw new Error("Unknown DID");
      return { did, identityDidKey: sourceKeys.identityDidKey,
        messagingDidKey: sourceKeys.messagingDidKey, serviceBase: sourceBase,
        evidence: { document: {}, data: { rotationKeys: [recovery.did(), sourceKeys.rotationDidKey] }, log: [op] } };
    } };
    await source.sql`INSERT INTO provider_accounts (id, tenant_id, canonical_address, did,
      onboarding_state, activated_at, activation_binding_digest, activation_verification_mode)
      VALUES (${accountId}, ${randomUUID()}, ${`cancel-${accountId}@source.example.com`},
        ${did}, 'active', now(), ${randomBytes(32)}, 'public')`;
    for (const key of sourceKeys.keys.filter((entry) => entry.role !== "hail-identity")) {
      await source.sql`INSERT INTO account_keys
        (account_id, role, algorithm, public_key, encrypted_private_key,
         encryption_nonce, encryption_version, kek_id)
        VALUES (${accountId}, ${key.role}, ${key.algorithm}, ${key.publicKey},
          ${key.ciphertext}, ${key.nonce}, ${key.encryptionVersion}, ${key.kekId})`;
    }
    await source.sql`INSERT INTO portable_custody_evidence
      (account_id, user_recovery_public_key, user_identity_public_key,
       monitor_origin, monitor_public_key, monitor_confirmed_at, backup_confirmed_at)
      VALUES (${accountId}, ${recovery.did()}, ${sourceKeys.identityDidKey},
        'https://monitor.example.com', ${sourceKeys.identityDidKey}, now(), now())`;
    const now = Math.floor(Date.now() / 1000);
    grant = await signHandshake({ type: "hail.transfer-grant", version: 1,
      did, nonce: randomUUID(), source_service_base: sourceBase,
      destination_service_base: targetBase, destination_domain: "target.example.com",
      issued_at: now, expires_at: now + 3600 } satisfies TransferGrant, userKey);
    const messaging = sourceKeys.keys.find((entry) => entry.role === "hail-messaging")!;
    const plaintext = await sourceEncryptor.decrypt(accountId,
      messaging.role, messaging.algorithm, messaging.publicKey, messaging);
    try { invitation = await new TransferInvitationService(source.sql, resolver, sourceBase)
      .issue(grant, await importEd25519PrivateKey(plaintext)); }
    finally { plaintext.fill(0); }
    targetKeys = new PreparedMigrationTarget(target.sql,
      new KeyEncryptor(encodeBase64Url(randomBytes(32))), targetBase);
    const receiver = new TransferInvitationReceiver(target.sql, resolver, targetKeys);
    const delivery = new TransferInvitationDelivery(source.sql, resolver, sourceBase,
      async () => { const signed = await receiver.receive(grant, invitation);
        const { requestWire, TRANSFER_MEDIA_TYPE } = await import("../src/migration/wire.js");
        return new Response(Uint8Array.from(requestWire(signed)), { status: 200,
          headers: { "Content-Type": TRANSFER_MEDIA_TYPE } }); },
      () => {});
    offer = await delivery.deliver(did);
    transferId = (decodeDeterministic(offer.payloadBytes) as unknown as { transfer_id: string }).transfer_id;
  });
  afterAll(async () => { if (source) await source.close(); if (target) await target.close(); });

  it("keeps source active after an ambiguous push, then releases target only on the source's signed no-fence receipt", async () => {
    const values = decodeDeterministic(grant.payloadBytes) as unknown as TransferGrant;
    const now = Math.floor(Date.now() / 1000);
    const address = `cancel-${randomUUID()}@target.example.com`;
    const selection = await signHandshake({ type: "hail.transfer-address-selection", version: 1,
      did, nonce: values.nonce, transfer_id: transferId, grant_digest: handshakeDigest(grant.payloadBytes),
      offer_digest: handshakeDigest(offer.payloadBytes), address,
      selection_nonce: randomUUID(), issued_at: now, expires_at: now + 1800,
    } satisfies TransferAddressSelection, userKey);
    const reserved = await new TransferAddressReservation(target.sql, resolver, targetKeys).reserve(selection);
    const publisher = new TransferFinalRequestPublisher(target.sql, resolver, targetKeys,
      async () => { throw new Error("Ambiguous response before old provider acknowledged"); }, () => {});
    await expect(publisher.publish(transferId)).rejects.toThrow("Ambiguous response");
    const pendingRequest = await target.sql<{ final_request_bytes: Uint8Array;
      final_request_signature: Uint8Array }[]>`
        SELECT final_request_bytes, final_request_signature FROM received_transfer_invitations
        WHERE transfer_id = ${transferId}`;
    await target.sql`UPDATE received_transfer_invitations
      SET next_final_attempt_at = clock_timestamp() WHERE transfer_id = ${transferId}`;
    const retryWorker = new TransferDeliveryWorker(target.sql, { async deliver() {
      throw new Error("Unexpected source invitation retry");
    } }, publisher);
    expect(await retryWorker.runOnce()).toBe("final");
    const retry = await target.sql<{ final_attempts: number; final_lease_token: string | null;
      next_final_attempt_at: Date }[]>`
      SELECT final_attempts, final_lease_token, next_final_attempt_at
      FROM received_transfer_invitations WHERE transfer_id = ${transferId}`;
    expect(retry[0]?.final_attempts).toBe(1);
    expect(retry[0]?.final_lease_token).toBeNull();
    expect(retry[0]!.next_final_attempt_at.getTime()).toBeGreaterThan(Date.now());
    await source.sql`UPDATE provider_transfer_authorizations
      SET expires_at = clock_timestamp() - interval '1 second' WHERE did = ${did}`;
    const reattempt = await signHandshake({ ...values, nonce: randomUUID(),
      issued_at: now, expires_at: now + 3600 } satisfies TransferGrant, userKey);
    const providerKey = sourceKeys.keys.find((entry) => entry.role === "hail-messaging")!;
    const providerBytes = await sourceEncryptor.decrypt(
      (await source.sql<{ id: string }[]>`SELECT id FROM provider_accounts WHERE did = ${did}`)[0]!.id,
      providerKey.role, providerKey.algorithm, providerKey.publicKey, providerKey);
    try {
      await expect(new TransferInvitationService(source.sql, resolver, sourceBase)
        .issue(reattempt, await importEd25519PrivateKey(providerBytes)))
        .rejects.toThrow("unresolved transfer grant");
    } finally { providerBytes.fill(0); }
    expect(await new MigrationFenceService(source.sql, resolver, sourceBase).get(did)).toBeNull();
    const before = await target.sql`SELECT canonical_address FROM provider_accounts
      WHERE canonical_address = ${address}`;
    expect(before).toHaveLength(1);
    const signedCancel = await signHandshake({ type: "hail.transfer-cancellation", version: 1,
      did, nonce: values.nonce, grant_digest: handshakeDigest(grant.payloadBytes),
      issued_at: now, expires_at: now + 3600 } satisfies TransferCancellation, userKey);
    const sourceCancellation = new TransferCancellationService(source.sql, resolver, sourceBase,
      new OnboardingRepository(source.sql), sourceEncryptor);
    const sourceRoutes = new Hono();
    registerTransferRoutes(sourceRoutes, new TransferInvitationReceiver(source.sql, resolver,
      new PreparedMigrationTarget(source.sql, sourceEncryptor, sourceBase)), undefined,
    new MigrationFenceService(source.sql, resolver, sourceBase), undefined, undefined, undefined,
    sourceCancellation);
    const sourceResult = await sourceRoutes.request("https://source.example.com/hail/transfers/cancellations",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(requestWire(signedCancel)) });
    expect(sourceResult.status).toBe(200);
    const signedReceipt = parseRequestWire(new Uint8Array(await sourceResult.arrayBuffer()));
    expect(await sourceCancellation.cancel(signedCancel)).toEqual(signedReceipt);
    await expect(new MigrationFenceService(source.sql, resolver, sourceBase)
      .begin({ payloadBytes: pendingRequest[0]!.final_request_bytes,
        signature: pendingRequest[0]!.final_request_signature }, selection, reserved.receipt))
      .rejects.toThrow("No valid user-authorized invitation");
    const targetCancellation = new TransferCancellationReceiver(target.sql, resolver, targetBase);
    const targetRoutes = new Hono();
    registerTransferRoutes(targetRoutes, new TransferInvitationReceiver(target.sql, resolver, targetKeys),
      undefined, undefined, undefined, undefined, undefined, undefined, targetCancellation);
    const forward = () => targetRoutes.request("https://target.example.com/.well-known/hail/transfers/cancellations",
      { method: "POST", headers: { "Content-Type": TRANSFER_MEDIA_TYPE },
        body: Uint8Array.from(cancellationWire(signedCancel, signedReceipt)) });
    expect((await forward()).status).toBe(204);
    expect((await forward()).status).toBe(204);
    expect(await target.sql`SELECT transfer_id FROM prepared_migration_target_keys
      WHERE transfer_id = ${transferId}`).toHaveLength(0);
    expect(await target.sql`SELECT canonical_address FROM provider_accounts
      WHERE canonical_address = ${address}`).toHaveLength(0);
    await expect(new TransferInvitationReceiver(target.sql, resolver, targetKeys)
      .receive(grant, invitation)).rejects.toThrow("cancelled");
    expect(await source.sql`SELECT cancelled_at FROM provider_transfer_authorizations
      WHERE did = ${did}`).toHaveLength(1);
  });
});
