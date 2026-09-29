import type { SQL } from "bun";
import { canonicalizeHailServiceBase, type HailDidResolver } from "../plc/resolver.js";
import { ed25519PublicKeyFromDidKey } from "../identity/did-key.js";
import { encodeDeterministic } from "@hailproto/codec";
import { verifyActivationReceipt, type SignedActivationReceipt } from "./activation-receipt.js";

export interface MigrationFence {
  did: string;
  accountId: string;
  transferId: string;
  destinationServiceBase: string;
  destinationRotationPublicKey: string;
  destinationMessagingPublicKey: string;
  state: "fenced" | "exported" | "retired";
  snapshotDigest: Uint8Array | null;
}

interface FenceRow {
  did: string;
  account_id: string;
  transfer_id: string;
  destination_service_base: string;
  destination_rotation_public_key: string | null;
  destination_messaging_public_key: string | null;
  state: MigrationFence["state"];
  snapshot_digest: Uint8Array | null;
}

function fromRow(row: FenceRow): MigrationFence {
  return { did: row.did, accountId: row.account_id, transferId: row.transfer_id,
    destinationServiceBase: row.destination_service_base,
    destinationRotationPublicKey: row.destination_rotation_public_key ?? "",
    destinationMessagingPublicKey: row.destination_messaging_public_key ?? "",
    state: row.state,
    snapshotDigest: row.snapshot_digest ? new Uint8Array(row.snapshot_digest) : null };
}

export class MigrationFenceService {
  constructor(
    private readonly sql: SQL,
    private readonly resolver: HailDidResolver,
    private readonly sourceServiceBase: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async begin(did: string, destinationInput: string,
    destinationRotationPublicKey: string, destinationMessagingPublicKey: string,
    transferId: string): Promise<MigrationFence> {
    const destination = canonicalizeHailServiceBase(destinationInput);
    if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(transferId)) {
      throw new Error("Destination preparation requires a canonical transfer ID");
    }
    if (destination === this.sourceServiceBase) throw new Error("Migration destination must differ from the source");
    if (!destinationRotationPublicKey.startsWith("did:key:z") ||
      destinationRotationPublicKey === destinationMessagingPublicKey) {
      throw new Error("Destination provider must supply a distinct PLC rotation key");
    }
    await ed25519PublicKeyFromDidKey(destinationMessagingPublicKey);
    const resolved = await this.resolver.resolve(did);
    if (resolved.did !== did || resolved.serviceBase !== this.sourceServiceBase) {
      throw new Error("Current PLC state does not authorize this provider as the source");
    }
    return this.sql.begin(async (tx) => {
      const accounts = await tx<{ id: string; onboarding_state: string; activation_verification_mode: string | null }[]>`
        SELECT id, onboarding_state, activation_verification_mode FROM provider_accounts
        WHERE did = ${did} FOR UPDATE
      `;
      const account = accounts[0];
      if (!account || account.onboarding_state !== "active" ||
        account.activation_verification_mode !== "public") {
        throw new Error("Migration source DID requires public activation");
      }
      const custody = await tx<{ user_recovery_public_key: string; user_identity_public_key: string }[]>`
        SELECT user_recovery_public_key, user_identity_public_key
        FROM portable_custody_evidence WHERE account_id = ${account.id}
      `;
      const evidence = custody[0];
      const data = resolved.evidence.data as { rotationKeys?: unknown };
      const rotationKeys: unknown[] | null = Array.isArray(data.rotationKeys) ? data.rotationKeys : null;
      const keys = await tx<{ role: string; public_key: string }[]>`
        SELECT role, public_key FROM account_keys WHERE account_id = ${account.id}
      `;
      if (!evidence || evidence.user_identity_public_key !== resolved.identityDidKey ||
        !rotationKeys || rotationKeys[0] !== evidence.user_recovery_public_key ||
        !keys.some((key) => key.role === "plc-rotation" && rotationKeys.slice(1).includes(key.public_key)) ||
        !keys.some((key) => key.role === "hail-messaging" && key.public_key === resolved.messagingDidKey) ||
        keys.some((key) => key.role === "hail-identity") ||
        rotationKeys.includes(destinationRotationPublicKey) ||
        destinationMessagingPublicKey === resolved.messagingDidKey) {
        throw new Error("Source does not satisfy portable custody or destination-key separation");
      }
      const existing = await tx<FenceRow[]>`
        SELECT did, account_id, transfer_id, destination_service_base,
          destination_rotation_public_key, destination_messaging_public_key, state, snapshot_digest
        FROM provider_migration_fences WHERE did = ${did}
      `;
      if (existing[0]) {
        if (existing[0].destination_service_base !== destination ||
          existing[0].destination_rotation_public_key !== destinationRotationPublicKey ||
          existing[0].destination_messaging_public_key !== destinationMessagingPublicKey ||
          existing[0].transfer_id !== transferId) {
          throw new Error("DID is already fenced for another destination");
        }
        return fromRow(existing[0]);
      }
      const rows = await tx<FenceRow[]>`
        INSERT INTO provider_migration_fences
          (did, account_id, transfer_id, destination_service_base,
           destination_rotation_public_key, destination_messaging_public_key, state)
        VALUES (${did}, ${account.id}, ${transferId}, ${destination},
          ${destinationRotationPublicKey}, ${destinationMessagingPublicKey}, 'fenced')
        RETURNING did, account_id, transfer_id, destination_service_base,
          destination_rotation_public_key, destination_messaging_public_key, state, snapshot_digest
      `;
      return fromRow(rows[0]!);
    });
  }

  async get(did: string): Promise<MigrationFence | null> {
    const rows = await this.sql<FenceRow[]>`
      SELECT did, account_id, transfer_id, destination_service_base,
        destination_rotation_public_key, destination_messaging_public_key, state, snapshot_digest
      FROM provider_migration_fences WHERE did = ${did}
    `;
    return rows[0] ? fromRow(rows[0]) : null;
  }

  // A pre-export abort cannot have produced an acknowledged import. Once
  // exported, release requires invalidating the receiving side first.
  async releaseBeforeExport(did: string, transferId: string): Promise<void> {
    await this.sql.begin(async (tx) => {
      const rows = await tx<FenceRow[]>`
        SELECT did, account_id, transfer_id, destination_service_base,
          destination_rotation_public_key, destination_messaging_public_key, state, snapshot_digest
        FROM provider_migration_fences WHERE did = ${did} FOR UPDATE
      `;
      if (!rows[0] || rows[0].transfer_id !== transferId || rows[0].state !== "fenced") {
        throw new Error("Only an unexported matching migration fence can be released");
      }
      await tx`DELETE FROM provider_migration_fences WHERE did = ${did} AND transfer_id = ${transferId}`;
    });
  }

  async retire(did: string, transferId: string, signed: SignedActivationReceipt): Promise<void> {
    const resolved = await this.resolver.resolve(did);
    return this.sql.begin(async (tx) => {
      const fences = await tx<(FenceRow & { fenced_at: Date })[]>`
        SELECT did, account_id, transfer_id, destination_service_base,
          destination_rotation_public_key, destination_messaging_public_key,
          state, snapshot_digest, fenced_at
        FROM provider_migration_fences WHERE did = ${did} AND transfer_id = ${transferId} FOR UPDATE
      `;
      const fence = fences[0];
      if (!fence || fence.state !== "exported" || !fence.snapshot_digest ||
        resolved.did !== did || resolved.serviceBase !== fence.destination_service_base ||
        resolved.messagingDidKey !== fence.destination_messaging_public_key) {
        throw new Error("Old provider cannot retire before authenticated destination cutover");
      }
      const receipt = await verifyActivationReceipt(signed, resolved.messagingDidKey,
        Math.floor(this.now().getTime() / 1000));
      if (receipt.did !== did || receipt.transfer_id !== transferId ||
        receipt.destination_service_base !== fence.destination_service_base ||
        receipt.activated_at < Math.floor(fence.fenced_at.getTime() / 1000) ||
        !Buffer.from(receipt.snapshot_digest).equals(Buffer.from(fence.snapshot_digest))) {
        throw new Error("Destination activation receipt does not match the fenced snapshot");
      }
      const bytes = encodeDeterministic({ payload: signed.payloadBytes, signature: signed.signature });
      await tx`
        UPDATE provider_migration_fences SET state = 'retired', retirement_receipt_bytes = ${bytes},
          retired_at = clock_timestamp(), updated_at = clock_timestamp()
        WHERE did = ${did} AND transfer_id = ${transferId} AND state = 'exported'
      `;
    });
  }
}
