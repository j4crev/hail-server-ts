import { createHash, randomBytes, randomUUID } from "node:crypto";
import { encodeBase64Url } from "@hailproto/codec";
import type { SQL } from "bun";
import { canonicalizeHailAddress } from "../identity/address.js";

export const ALL_ACCOUNT_SCOPES = ["account:read","grants:read","grants:write","credentials:write","messages:read","messages:write"] as const;
export type AccountApiScope = typeof ALL_ACCOUNT_SCOPES[number];
export interface AccountApiSession {
  account_id: string;
  did: string;
  canonical_address: string;
  scopes: AccountApiScope[];
  migration_state: "fenced" | "exported" | "retired" | null;
}
export const tokenHash = (token: string) => new Uint8Array(createHash("sha256").update(token).digest());

export class AccountApiRepository {
  constructor(private readonly sql: SQL) {}

  async issue(address: string, writeGrants = false, suppliedToken?: string, requestedScopes?: AccountApiScope[]) {
    const token = suppliedToken ?? `hailp_${encodeBase64Url(randomBytes(32))}`;
    if (!/^hailp_[A-Za-z0-9_-]{43}$/.test(token)) throw new Error("Invalid API token");
    const id = randomUUID();
    const scopes: AccountApiScope[] = requestedScopes ?? ["account:read", "grants:read", ...(writeGrants ? ["grants:write" as const] : [])];
    return this.sql.begin(async (tx) => {
      const accounts = await tx<{ id: string }[]>`
        SELECT id FROM provider_accounts WHERE canonical_address = ${canonicalizeHailAddress(address)}
          AND onboarding_state = 'active' AND did IS NOT NULL FOR UPDATE`;
      const account = accounts[0];
      if (!account) throw new Error("API credentials require an existing active account");
      const fenced = await tx`SELECT did FROM provider_migration_fences WHERE account_id = ${account.id}`;
      if (fenced.length) throw new Error("Cannot issue credentials for a migration-fenced account");
      const prior = await tx<{id:string;account_id:string;expires_at:Date;revoked_at:Date|null;scopes:unknown}[]>`
        SELECT id,account_id,expires_at,revoked_at,scopes FROM account_api_credentials WHERE token_hash=${tokenHash(token)}`;
      if (prior[0]) {
        if (prior[0].account_id !== account.id || prior[0].revoked_at || prior[0].expires_at.getTime() <= Date.now()) throw new Error("Credential cannot be reused");
        return {credentialId:prior[0].id,accountId:account.id,token,scopes:typeof prior[0].scopes === "string" ? JSON.parse(prior[0].scopes) as AccountApiScope[] : prior[0].scopes as AccountApiScope[],expiresAt:prior[0].expires_at.toISOString()};
      }
      const rows = await tx<{ expires_at: Date }[]>`
        INSERT INTO account_api_credentials (id, account_id, token_hash, scopes, expires_at)
        VALUES (${id}, ${account.id}, ${tokenHash(token)}, (${JSON.stringify(scopes)}::text)::jsonb,
          now() + interval '30 days') RETURNING expires_at`;
      return { credentialId: id, accountId: account.id, token, scopes, expiresAt: rows[0]!.expires_at.toISOString() };
    });
  }

  async revoke(id: string, accountId?: string): Promise<void> {
    if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(id)) throw new Error("Credential ID must be a canonical UUID");
    const rows = await this.sql`UPDATE account_api_credentials SET revoked_at = COALESCE(revoked_at, now())
      WHERE id = ${id} AND (${accountId ?? null}::uuid IS NULL OR account_id=${accountId ?? null}::uuid) RETURNING id`;
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
    const managed = await this.sql<{owner_recovery_public_key:string}[]>`SELECT owner_recovery_public_key FROM managed_custody_evidence WHERE account_id=${session.account_id}`;
    const profile = managed[0] && identity ? "managed" : custody[0] && !identity ? "owner-controlled" : !custody[0] && identity && rotation ?
      "custodial-poc" : "unknown";
    return { type: "hailp.account", version: 1, provider, accountId: session.account_id,
      did: session.did, address: session.canonical_address, migrationState: session.migration_state,
      custodyProfile: profile, monitorVerificationMode: managed[0] ? "poc-local" : custody[0]?.monitor_verification_mode ?? null,
      identityPublicKey: custody[0]?.user_identity_public_key ?? identity?.public_key ?? null,
      ownerRecoveryPublicKey: managed[0]?.owner_recovery_public_key ?? custody[0]?.user_recovery_public_key ?? null, scopes: session.scopes };
  }

  async isManaged(accountId: string) { return (await this.sql`SELECT account_id FROM managed_custody_evidence WHERE account_id=${accountId}`).length === 1; }

  async listGrants(session: AccountApiSession, after: string | null) {
    const rows = await this.sql<{ grant_id: string; local_role: string; grantor_did: string;
      grantee_did: string; current_revision: number; current_status: string; expires_at: number | null }[]>`
      SELECT lineage.grant_id, CASE WHEN lineage.local_account_id = ${session.account_id}
        THEN lineage.local_role ELSE 'grantee' END AS local_role, lineage.grantor_did,lineage.grantee_did,
        lineage.current_revision,lineage.current_status,revision.expires_at
      FROM grant_lineages lineage JOIN grant_revisions revision ON revision.grant_id=lineage.grant_id
        AND revision.revision=lineage.current_revision
      WHERE (lineage.local_account_id=${session.account_id} OR EXISTS (
        SELECT 1 FROM collocated_grant_receivers local WHERE local.grant_id=lineage.grant_id
          AND local.grantee_account_id=${session.account_id}))
        AND (${after}::uuid IS NULL OR lineage.grant_id > ${after}::uuid)
      ORDER BY lineage.grant_id LIMIT 51`;
    return { grants: rows.slice(0,50).map(row => ({ grantId: row.grant_id, localRole: row.local_role,
      grantor: row.grantor_did, grantee: row.grantee_did, revision: row.current_revision,
      status: row.current_status, expiresAt: row.expires_at === null ? null : Number(row.expires_at) })),
      next: rows.length > 50 ? rows[49]!.grant_id : null };
  }
}
