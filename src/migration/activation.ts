import { createHash, randomUUID } from "node:crypto";
import { signPayload, inspectSignedPayload, type HailSenderProfile } from "@hailproto/codec";
import { createWebCryptoSigner } from "@hailproto/codec";
import type { SQL } from "bun";
import type { VerifiedAddress } from "../discovery/verifier.js";
import type { KeyEncryptor } from "../identity/key-encryption.js";
import { importEd25519PrivateKey } from "../identity/keys.js";
import type { HailDidResolver } from "../plc/resolver.js";
import { parseJsonWithoutDuplicateKeys } from "../discovery/strict-json.js";
import { PortableCutoverGate } from "./cutover-gate.js";
import type { SignedMonitorAttestation } from "./monitor-attestation.js";
import { PreparedMigrationTarget } from "./target-keys.js";
import { validateTransferManifest, type TransferManifest } from "./transfer.js";
import { signActivationReceipt, type SignedActivationReceipt } from "./activation-receipt.js";

type TableRow = Record<string, unknown>;

function key(row: TableRow): string { return `${row.sender_did}\0${row.message_id}`; }

async function insertRow(sql: SQL, table: string, row: TableRow): Promise<void> {
  // Table names are constants below, never supplied by a snapshot or caller.
  await sql.unsafe(`INSERT INTO "${table}" SELECT * FROM jsonb_populate_record(NULL::"${table}", ($1::text)::jsonb)`,
    [JSON.stringify(row)]);
}

export interface PortableAddressVerifier {
  verify(address: string): Promise<VerifiedAddress>;
}

export class PortableMigrationActivation {
  constructor(
    private readonly sql: SQL,
    private readonly encryptor: KeyEncryptor,
    private readonly resolver: HailDidResolver,
    private readonly gate: PortableCutoverGate,
    private readonly addressVerifier: PortableAddressVerifier,
    private readonly serviceBase: string,
    private readonly registryOrigin: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async issueReceipt(transferId: string): Promise<SignedActivationReceipt> {
    const rows = await this.sql<{ state: string; did: string; manifest_digest: Uint8Array;
      destination_address: string; destination_binding_digest: Uint8Array; activated_at: Date }[]>`
      SELECT state, did, manifest_digest, destination_address, destination_binding_digest, activated_at
      FROM pending_migration_imports WHERE transfer_id = ${transferId}
    `;
    const row = rows[0];
    if (!row || row.state !== "active" || !row.activated_at) {
      throw new Error("Only an active imported DID may acknowledge destination takeover");
    }
    const resolved = await this.resolver.resolve(row.did);
    if (resolved.serviceBase !== this.serviceBase) throw new Error("PLC no longer designates the destination");
    const keys = await this.sql<{ id: string; public_key: string; encrypted_private_key: Uint8Array;
      encryption_nonce: Uint8Array }[]>`
      SELECT account.id, key.public_key, key.encrypted_private_key, key.encryption_nonce
      FROM provider_accounts account JOIN account_keys key ON key.account_id = account.id
      WHERE account.did = ${row.did} AND key.role = 'hail-messaging'
    `;
    const key = keys[0];
    if (!key || key.public_key !== resolved.messagingDidKey) throw new Error("Current messaging key is unavailable");
    const plaintext = await this.encryptor.decrypt(key.id, "hail-messaging", "ed25519", key.public_key, {
      ciphertext: key.encrypted_private_key, nonce: key.encryption_nonce, encryptionVersion: 1, kekId: "poc-v1",
    });
    try {
      return signActivationReceipt({ type: "hail.portable-migration-activated", version: 1,
        did: row.did, transfer_id: transferId, snapshot_digest: new Uint8Array(row.manifest_digest),
        destination_service_base: this.serviceBase, destination_messaging_key: key.public_key,
        destination_address: row.destination_address,
        address_binding_digest: new Uint8Array(row.destination_binding_digest),
        activated_at: Math.floor(row.activated_at.getTime() / 1000),
      }, await importEd25519PrivateKey(plaintext));
    } finally { plaintext.fill(0); }
  }

  async activate(transferId: string, signedMonitor: SignedMonitorAttestation): Promise<{ did: string; accountId: string }> {
    if (this.registryOrigin !== "https://plc.directory") {
      throw new Error("Portable activation requires the canonical public PLC write registry");
    }
    const assessment = await this.gate.assess(transferId, signedMonitor);
    if (!assessment.eligible) throw new Error("PLC recovery quarantine has not completed");
    const imports = await this.sql<{ state: string; did: string; manifest_bytes: Uint8Array;
      destination_binding_cose: Uint8Array; destination_binding_digest: Uint8Array;
      destination_address: string; signed_plc_operation_bytes: Uint8Array }[]>`
      SELECT state, did, manifest_bytes, destination_binding_cose, destination_binding_digest,
        destination_address, signed_plc_operation_bytes
      FROM pending_migration_imports WHERE transfer_id = ${transferId}
    `;
    const pending = imports[0];
    if (!pending || pending.state !== "staged") throw new Error("No inactive validated transfer to activate");
    const manifest = validateTransferManifest(pending.manifest_bytes);
    if (manifest.did !== pending.did || manifest.destinationServiceBase !== this.serviceBase ||
      manifest.transferId !== transferId ||
      assessment.operationCid !== (await this.currentOperationCid(pending.signed_plc_operation_bytes))) {
      throw new Error("Cutover evidence does not match the staged operation");
    }
    const resolved = await this.resolver.resolve(manifest.did);
    if (resolved.serviceBase !== this.serviceBase ||
      resolved.messagingDidKey !== manifest.destinationMessagingPublicKey ||
      resolved.identityDidKey !== manifest.tables.portable_custody_evidence[0]?.user_identity_public_key) {
      throw new Error("Current PLC does not designate the prepared destination");
    }
    const address = await this.addressVerifier.verify(pending.destination_address);
    if (address.address !== pending.destination_address || address.did !== manifest.did ||
      address.serviceBase !== this.serviceBase || address.messagingDidKey !== manifest.destinationMessagingPublicKey ||
      address.identityDidKey !== resolved.identityDidKey ||
      !Buffer.from(address.digest).equals(Buffer.from(pending.destination_binding_digest)) ||
      !Buffer.from(address.representation).equals(Buffer.from(pending.destination_binding_cose))) {
      throw new Error("Destination address does not select the exact user-signed binding");
    }
    const prepared = { transferId, did: manifest.did, destinationServiceBase: this.serviceBase,
      rotationPublicKey: manifest.destinationRotationPublicKey,
      messagingPublicKey: manifest.destinationMessagingPublicKey };
    await new PreparedMigrationTarget(this.sql, this.encryptor, this.serviceBase).assertOwnership(prepared);
    const keys = await this.sql<{ rotation_private_ciphertext: Uint8Array; rotation_nonce: Uint8Array;
      messaging_private_ciphertext: Uint8Array; messaging_nonce: Uint8Array; state: string }[]>`
      SELECT rotation_private_ciphertext, rotation_nonce, messaging_private_ciphertext, messaging_nonce, state
      FROM prepared_migration_target_keys WHERE transfer_id = ${transferId}
    `;
    if (!keys[0] || keys[0].state !== "staged") throw new Error("Prepared destination keys are not staged");
    const rotationBytes = await this.encryptor.decrypt(transferId, "plc-rotation", "p256",
      prepared.rotationPublicKey, { ciphertext: keys[0].rotation_private_ciphertext,
        nonce: keys[0].rotation_nonce, encryptionVersion: 1, kekId: "poc-v1" });
    const messagingBytes = await this.encryptor.decrypt(transferId, "hail-messaging", "ed25519",
      prepared.messagingPublicKey, { ciphertext: keys[0].messaging_private_ciphertext,
        nonce: keys[0].messaging_nonce, encryptionVersion: 1, kekId: "poc-v1" });
    let rotation;
    let messaging;
    let messagingKey: CryptoKey;
    try {
      messagingKey = await importEd25519PrivateKey(messagingBytes);
      [rotation, messaging] = await Promise.all([
        this.encryptor.encrypt(manifest.accountId, "plc-rotation", "p256", prepared.rotationPublicKey, rotationBytes),
        this.encryptor.encrypt(manifest.accountId, "hail-messaging", "ed25519", prepared.messagingPublicKey, messagingBytes),
      ]);
    } finally { rotationBytes.fill(0); messagingBytes.fill(0); }
    return this.sql.begin(async (tx) => {
      const importsLocked = await tx<{ state: string }[]>`
        SELECT state FROM pending_migration_imports WHERE transfer_id = ${transferId} FOR UPDATE
      `;
      const preparedKeys = await tx<{ state: string }[]>`
        SELECT state FROM prepared_migration_target_keys WHERE transfer_id = ${transferId} FOR UPDATE
      `;
      const gate = await tx<{ state: string; last_seen_at: Date; operation_cid: string }[]>`
        SELECT state, last_seen_at, operation_cid FROM portable_cutover_observations
        WHERE transfer_id = ${transferId} FOR UPDATE
      `;
      if (importsLocked[0]?.state !== "staged" || preparedKeys[0]?.state !== "staged" ||
        gate[0]?.state !== "eligible" ||
        gate[0].operation_cid !== assessment.operationCid ||
        Math.abs(this.now().getTime() - gate[0].last_seen_at.getTime()) > 30_000) {
        throw new Error("Current cutover eligibility was lost before materialization");
      }
      const accounts = await tx<{ id: string }[]>`SELECT id FROM provider_accounts WHERE did = ${manifest.did}`;
      if (accounts.length) throw new Error("Target already has an active account for the DID");
      const reserved = await tx<{ reserved_account_id: string | null; canonical_address: string; state: string }[]>`
        SELECT reserved_account_id, canonical_address, state FROM transfer_address_reservations
        WHERE transfer_id = ${transferId} AND did = ${manifest.did} FOR UPDATE`;
      if (!reserved[0]?.reserved_account_id || reserved[0].canonical_address !== pending.destination_address ||
        reserved[0].state !== "submitted") {
        throw new Error("Destination address reservation was lost before activation");
      }
      const released = await tx`DELETE FROM provider_accounts WHERE id = ${reserved[0].reserved_account_id}
        AND canonical_address = ${pending.destination_address} AND did IS NULL
        AND onboarding_state = 'reserved' RETURNING id`;
      if (released.length !== 1) throw new Error("Destination address was assigned elsewhere");
      await insertRow(tx, "provider_accounts", {
        ...manifest.tables.provider_accounts[0]!, canonical_address: pending.destination_address,
        activation_binding_digest: `\\x${Buffer.from(address.digest).toString("hex")}`,
        activation_verification_mode: "public", activated_at: this.now().toISOString(),
      });
      for (const [role, algorithm, publicKey, material] of [
        ["plc-rotation", "p256", prepared.rotationPublicKey, rotation],
        ["hail-messaging", "ed25519", prepared.messagingPublicKey, messaging],
      ] as const) {
        await tx`
          INSERT INTO account_keys (account_id, role, algorithm, public_key, encrypted_private_key,
            encryption_nonce, encryption_version, kek_id)
          VALUES (${manifest.accountId}, ${role}, ${algorithm}, ${publicKey}, ${material.ciphertext},
            ${material.nonce}, 1, 'poc-v1')
        `;
      }
      for (const table of ["portable_custody_evidence", "plc_operation_evidence", "address_bindings"] as const) {
        for (const row of manifest.tables[table]) await insertRow(tx, table, row);
      }
      const operation = parseJsonWithoutDuplicateKeys(new TextDecoder().decode(pending.signed_plc_operation_bytes));
      await tx`
        INSERT INTO plc_operation_evidence (id, account_id, did, operation_cid,
          previous_cid, registry_origin, signed_operation, signed_operation_bytes,
          dag_cbor, expected_state, submission_state, submitted_at, verified_at)
        VALUES (${randomUUID()}, ${manifest.accountId}, ${manifest.did}, ${assessment.operationCid},
          ${(operation as { prev: string }).prev}, ${this.registryOrigin},
          ${JSON.stringify(operation)}::jsonb, ${pending.signed_plc_operation_bytes},
          ${new Uint8Array((await import("@ipld/dag-cbor")).encode(operation))},
          ${JSON.stringify(resolved.evidence.data)}::jsonb, 'verified', now(), now())
      `;
      await tx`
        INSERT INTO address_bindings (id, account_id, canonical_address, did, cose,
          representation_digest, issued_at, expires_at, published_at, hosted_at, selected_at)
        VALUES (${randomUUID()}, ${manifest.accountId}, ${pending.destination_address}, ${manifest.did},
          ${pending.destination_binding_cose}, ${pending.destination_binding_digest},
          ${new Date(address.binding.issued_at * 1000)}, ${new Date(address.binding.expires_at * 1000)},
          now(), now(), now())
      `;
      for (const row of manifest.tables.sender_profiles) await insertRow(tx, "sender_profiles", row);
      await this.refreshProfile(tx, manifest, messagingKey, prepared.messagingPublicKey);
      for (const table of ["grant_lineages", "grant_revisions", "grant_consent_evidence",
        "grant_publications", "detached_bodies", "body_authorizations"] as const) {
        for (const row of manifest.tables[table]) {
          const resumed = table === "grant_publications" && ["pending", "retry"].includes(String(row.state))
            ? { ...row, lease_token: null, lease_expires_at: null, next_attempt_at: new Date().toISOString() }
            : row;
          await insertRow(tx, table, resumed);
        }
      }
      await this.importEnvelopes(tx, manifest);
      for (const table of ["reply_capabilities", "delivery_work", "verified_body_provenance",
        "delivered_messages", "delivery_status_payloads", "delivery_status_wrappers",
        "terminal_status_publications", "sent_delivery_status"] as const) {
        for (const row of manifest.tables[table]) {
          const resumed = ["delivery_work", "terminal_status_publications"].includes(table) &&
            ["accepted", "on-hold", "pending", "retry"].includes(String(row.state))
            ? { ...row, lease_token: null, lease_expires_at: null, next_attempt_at: new Date().toISOString() }
            : row;
          await insertRow(tx, table, resumed);
        }
      }
      const activated = await tx`UPDATE pending_migration_imports SET state = 'active', activated_at = ${this.now()}
        WHERE transfer_id = ${transferId} AND state = 'staged' RETURNING transfer_id`;
      const owned = await tx`UPDATE prepared_migration_target_keys SET state = 'active'
        WHERE transfer_id = ${transferId} AND state = 'staged' RETURNING transfer_id`;
      if (activated.length !== 1 || owned.length !== 1) {
        throw new Error("Destination ownership changed during activation");
      }
      await tx`UPDATE transfer_address_reservations SET state = 'active' WHERE transfer_id = ${transferId}`;
      return { did: manifest.did, accountId: manifest.accountId };
    });
  }

  private async currentOperationCid(bytes: Uint8Array): Promise<string> {
    const { cidForCbor } = await import("@atproto/common");
    const { def } = await import("@did-plc/lib");
    const operation = def.operation.parse(parseJsonWithoutDuplicateKeys(new TextDecoder().decode(bytes)));
    return (await cidForCbor(operation)).toString();
  }

  private async importEnvelopes(tx: SQL, manifest: TransferManifest): Promise<void> {
    const waiting = [
      ...manifest.tables.sent_envelopes.map((row) => ({ table: "sent_envelopes", row })),
      ...manifest.tables.received_envelopes.map((row) => ({ table: "received_envelopes", row })),
    ];
    const insertedSent = new Set<string>();
    const insertedReceived = new Set<string>();
    while (waiting.length > 0) {
      let progress = false;
      for (let index = waiting.length - 1; index >= 0; index -= 1) {
        const entry = waiting[index]!;
        const row = entry.row;
        const dependency = `${row.recipient_did}\0${row.reply_to_message_id}`;
        if (row.authorization_type === "reply" &&
          !(entry.table === "sent_envelopes" ? insertedReceived : insertedSent).has(dependency)) continue;
        await insertRow(tx, entry.table, row);
        (entry.table === "sent_envelopes" ? insertedSent : insertedReceived)
          .add(`${row.sender_did}\0${row.message_id}`);
        waiting.splice(index, 1);
        progress = true;
      }
      if (!progress) throw new Error("Imported reply envelopes contain an absent or cyclic original");
    }
  }

  private async refreshProfile(tx: SQL, manifest: TransferManifest,
    messagingKey: CryptoKey, publicKey: string): Promise<void> {
    const old = manifest.tables.sender_profiles.at(-1);
    if (!old) return;
    const representation = String(old.cose);
    if (!/^\\x[0-9a-f]+$/i.test(representation)) throw new Error("Imported Sender Profile bytes are invalid");
    const prior = inspectSignedPayload("hail.sender-profile", Buffer.from(representation.slice(2), "hex")).payload;
    const updatedAt = Math.max(Math.floor(this.now().getTime() / 1000), prior.updated_at + 1);
    const payload: HailSenderProfile = { ...prior, revision: prior.revision + 1,
      updated_at: updatedAt, key_id: `${manifest.did}#hail-messaging` };
    const cose = await signPayload("hail.sender-profile", payload,
      createWebCryptoSigner(`${manifest.did}#hail-messaging`, messagingKey));
    await tx`
      INSERT INTO sender_profiles (id, account_id, did, revision, profile_payload,
        cose, representation_digest, signing_public_key, profile_updated_at)
      VALUES (${randomUUID()}, ${manifest.accountId}, ${manifest.did}, ${payload.revision},
        ${payload}::jsonb, ${cose}, ${new Uint8Array(createHash("sha256").update(cose).digest())},
        ${publicKey}, ${updatedAt})
    `;
  }
}
