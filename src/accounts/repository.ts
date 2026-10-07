import { createHash, randomBytes, randomUUID } from "node:crypto";
import { encodeBase64Url } from "@hailproto/codec";
import type { SQL } from "bun";
import { canonicalizeHailAddress } from "../identity/address.js";

export type AccountApiScope = "account:read" | "grants:read" | "grants:write";
export interface AccountApiSession {
  account_id: string;
  did: string;
  canonical_address: string;
  scopes: AccountApiScope[];
  migration_state: "fenced" | "exported" | "retired" | null;
}
const tokenHash = (token: string) => new Uint8Array(createHash("sha256").update(token).digest());

export class AccountApiRepository {
  constructor(private readonly sql: SQL) {}

  async issue(address: string, writeGrants = false) {
    const token = `hailp_${encodeBase64Url(randomBytes(32))}`;
    const id = randomUUID();
    const scopes: AccountApiScope[] = ["account:read", "grants:read", ...(writeGrants ? ["grants:write" as const] : [])];
    return this.sql.begin(async (tx) => {
      const accounts = await tx<{ id: string }[]>`
        SELECT id FROM provider_accounts WHERE canonical_address = ${canonicalizeHailAddress(address)}
          AND onboarding_state = 'active' AND did IS NOT NULL FOR UPDATE`;
      const account = accounts[0];
      if (!account) throw new Error("API credentials require an existing active account");
      const fenced = await tx`SELECT did FROM provider_migration_fences WHERE account_id = ${account.id}`;
      if (fenced.length) throw new Error("Cannot issue credentials for a migration-fenced account");
      const rows = await tx<{ expires_at: Date }[]>`
        INSERT INTO account_api_credentials (id, account_id, token_hash, scopes, expires_at)
        VALUES (${id}, ${account.id}, ${tokenHash(token)}, (${JSON.stringify(scopes)}::text)::jsonb,
          now() + interval '30 days') RETURNING expires_at`;
      return { credentialId: id, accountId: account.id, token, scopes, expiresAt: rows[0]!.expires_at.toISOString() };
    });
  }

  async revoke(id: string): Promise<void> {
    if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(id)) throw new Error("Credential ID must be a canonical UUID");
    const rows = await this.sql`UPDATE account_api_credentials SET revoked_at = COALESCE(revoked_at, now())
      WHERE id = ${id} RETURNING id`;
    if (!rows.length) throw new Error("API credential does not exist");
  }

  async authenticate(header: string | undefined): Promise<AccountApiSession | null> {
    const token = /^Bearer (hailp_[A-Za-z0-9_-]{43})$/i.exec(header ?? "")?.[1];
    if (!token) return null;
    const rows = await this.sql<(Omit<AccountApiSession, "scopes"> & { scopes: unknown })[]>`
      SELECT account.id AS account_id, account.did, account.canonical_address,
        credential.scopes, fence.state AS migration_state
      FROM account_api_credentials credential JOIN provider_accounts account ON account.id = credential.account_id
      LEFT JOIN provider_migration_fences fence ON fence.account_id = account.id
      WHERE credential.token_hash = ${tokenHash(token)} AND credential.revoked_at IS NULL
        AND credential.expires_at > now() AND account.onboarding_state = 'active' AND account.did IS NOT NULL`;
    if (!rows[0]) return null;
    const scopes = typeof rows[0].scopes === "string" ? JSON.parse(rows[0].scopes) : rows[0].scopes;
    return { ...rows[0], scopes: scopes as AccountApiScope[] };
  }

  async describe(session: AccountApiSession, provider: string) {
    const custody = await this.sql<{ user_identity_public_key: string; user_recovery_public_key: string;
      monitor_verification_mode: string }[]>`
      SELECT user_identity_public_key, user_recovery_public_key, monitor_verification_mode
      FROM portable_custody_evidence WHERE account_id = ${session.account_id}`;
    const keys = await this.sql<{ role: string; public_key: string }[]>`
      SELECT role, public_key FROM account_keys WHERE account_id = ${session.account_id} ORDER BY role`;
    const identity = keys.find(key => key.role === "hail-identity");
    const rotation = keys.find(key => key.role === "plc-rotation");
    const profile = custody[0] && !identity ? "owner-controlled" : !custody[0] && identity && rotation ?
      "custodial-poc" : "unknown";
    return { type: "hailp.account", version: 1, provider, accountId: session.account_id,
      did: session.did, address: session.canonical_address, migrationState: session.migration_state,
      custodyProfile: profile, monitorVerificationMode: custody[0]?.monitor_verification_mode ?? null,
      identityPublicKey: custody[0]?.user_identity_public_key ?? identity?.public_key ?? null,
      ownerRecoveryPublicKey: custody[0]?.user_recovery_public_key ?? null, scopes: session.scopes };
  }
}
