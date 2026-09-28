import { createHash } from "node:crypto";
import { encodePayload, inspectSignedPayload, type HailEnvelope } from "@hailproto/codec";
import type { SQL } from "bun";
import type { PlcResolutionEvidence } from "../plc/resolver.js";

export interface PublishedBodyInfo { size: number; senderAccountId: string; }
export interface EnvelopeDecision {
  payload: HailEnvelope;
  representation: Uint8Array;
  payloadDigest: Uint8Array;
  envelopeDigest: Uint8Array;
  localAccountId: string;
  signingPublicKey: string;
  evidence: PlcResolutionEvidence;
  now: number;
}

export type EnvelopeOutcome = "accepted" | "duplicate" | "conflict" | "unauthorized" | "message-expired";

export class EnvelopeRepository {
  constructor(private readonly sql: SQL) {}

  async sent(senderDid: string, messageId: string): Promise<Uint8Array | null> {
    const rows = await this.sql<{ envelope_cose: Uint8Array }[]>`
      SELECT envelope_cose FROM sent_envelopes WHERE sender_did = ${senderDid} AND message_id = ${messageId}
    `;
    return rows[0] ? new Uint8Array(rows[0].envelope_cose) : null;
  }

  async publishedBody(senderDid: string, digest: Uint8Array): Promise<PublishedBodyInfo | null> {
    const rows = await this.sql<{ size: number; sender_account_id: string }[]>`
      SELECT octet_length(body.body_bytes) AS size, body.sender_account_id
      FROM detached_bodies body JOIN provider_accounts account ON account.id = body.sender_account_id
      WHERE body.digest = ${digest} AND account.did = ${senderDid}
        AND account.onboarding_state = 'active' AND account.activation_verification_mode = 'public'
    `;
    return rows[0] ? { size: rows[0].size, senderAccountId: rows[0].sender_account_id } : null;
  }

  async createSent(payload: HailEnvelope, representation: Uint8Array, accountId: string): Promise<void> {
    if (payload.authorization.type !== "grant") throw new Error("Only grant-authorized envelopes are supported");
    const grantId = payload.authorization.grant_id;
    const inspected = inspectSignedPayload("hail.envelope", representation);
    if (!Buffer.from(inspected.payloadBytes).equals(Buffer.from(encodePayload("hail.envelope", payload))) ||
      representation.length > 16_384) {
      throw new Error("Invalid signed envelope");
    }
    const tokenHash = createHash("sha256").update(payload.body.access.token).digest();
    const envelopeDigest = createHash("sha256").update(inspected.payloadBytes).digest();
    await this.sql.begin(async (tx) => {
      const accounts = await tx<{ id: string }[]>`
        SELECT id FROM provider_accounts WHERE id = ${accountId} AND did = ${payload.from}
          AND onboarding_state = 'active' AND activation_verification_mode = 'public' FOR UPDATE
      `;
      if (!accounts[0]) throw new Error("Sender is not publicly active");
      const bodies = await tx<{ size: number; available_until: string | bigint | number | null }[]>`
        SELECT octet_length(body_bytes) AS size, available_until FROM detached_bodies
        WHERE digest = ${payload.body.digest.value} AND sender_account_id = ${accountId} FOR UPDATE
      `;
      const body = bodies[0];
      if (!body || body.size !== payload.body.size) throw new Error("Signed body is not published");
      await tx`
        INSERT INTO sent_envelopes (sender_did, message_id, recipient_did, grant_id, envelope_cose,
          envelope_digest, body_digest, sender_account_id)
        VALUES (${payload.from}, ${payload.message_id}, ${payload.to}, ${grantId},
          ${representation}, ${envelopeDigest}, ${payload.body.digest.value}, ${accountId})
      `;
      await tx`
        INSERT INTO body_authorizations
          (token_hash, body_digest, sender_account_id, recipient_did, message_id, expires_at, available_until)
        VALUES (${tokenHash}, ${payload.body.digest.value}, ${accountId}, ${payload.to},
          ${payload.message_id}, ${payload.body.access.expires_at}, ${payload.body.available_until})
      `;
      if (body.available_until === null || Number(body.available_until) < payload.body.available_until) {
        await tx`UPDATE detached_bodies SET available_until = ${payload.body.available_until}
          WHERE digest = ${payload.body.digest.value} AND sender_account_id = ${accountId}`;
      }
    });
  }

  async candidate(grantId: string, from: string, to: string): Promise<boolean> {
    const rows = await this.sql<{ grant_id: string }[]>`
      SELECT grant_id FROM grant_lineages WHERE grant_id = ${grantId} AND grantor_did = ${to}
        AND grantee_did = ${from} AND local_role = 'grantor'
    `;
    return rows.length > 0;
  }

  async accept(input: EnvelopeDecision): Promise<EnvelopeOutcome> {
    const { payload, representation, envelopeDigest, payloadDigest, localAccountId, signingPublicKey, evidence } = input;
    if (payload.authorization.type !== "grant") return "unauthorized";
    const grantId = payload.authorization.grant_id;
    // Lock the grant pointer before inspecting its status or reserving the replay key.
    // Revocation and acceptance serialize on the same lineage row.
    return this.sql.begin(async (tx): Promise<EnvelopeOutcome> => {
      const lineages = await tx<{
        local_account_id: string; current_status: string; expires_at: string | number | bigint | null;
        scope_payload: unknown;
      }[]>`
        SELECT lineage.local_account_id, lineage.current_status, revision.expires_at, revision.scope_payload
        FROM grant_lineages lineage JOIN grant_revisions revision
          ON revision.grant_id = lineage.grant_id AND revision.revision = lineage.current_revision
        WHERE lineage.grant_id = ${grantId}
          AND lineage.grantor_did = ${payload.to} AND lineage.grantee_did = ${payload.from}
          AND lineage.local_role = 'grantor'
        FOR UPDATE OF lineage
      `;
      const lineage = lineages[0];
      if (!lineage || lineage.local_account_id !== localAccountId) return "unauthorized";
      const previous = await tx<{ payload_digest: Uint8Array }[]>`
        SELECT payload_digest FROM received_envelopes
        WHERE sender_did = ${payload.from} AND message_id = ${payload.message_id}
      `;
      if (previous[0]) {
        return Buffer.from(previous[0].payload_digest).equals(Buffer.from(payloadDigest)) ? "duplicate" : "conflict";
      }
      const clock = await tx<{ instant: string | number }[]>`SELECT extract(epoch from clock_timestamp()) AS instant`;
      const now = Number(clock[0]!.instant);
      const scope = typeof lineage.scope_payload === "string" ? JSON.parse(lineage.scope_payload) : lineage.scope_payload;
      const selector = Array.isArray(scope) ? scope[0] : null;
      const permitted = lineage.current_status === "active" &&
        (lineage.expires_at === null || Number(lineage.expires_at) >= now) &&
        ((selector?.type === "categories" && typeof payload.category === "string" && selector.values?.includes(payload.category)) ||
         (selector?.type === "uncategorized" && payload.category === undefined));
      const deadline = Math.min(payload.expires_at + 300, payload.body.available_until, payload.body.access.expires_at);
      const outcome = now > deadline ? "message-expired" : permitted ? "accepted" : "unauthorized";
      const inserted = await tx<{ payload_digest: Uint8Array }[]>`
        INSERT INTO received_envelopes
          (sender_did, message_id, recipient_did, grant_id, local_account_id, envelope_cose,
           envelope_digest, payload_digest, signing_public_key, signing_plc_document,
           signing_plc_data, signing_plc_operation_log, outcome, accepted_at)
        VALUES (${payload.from}, ${payload.message_id}, ${payload.to}, ${grantId},
          ${localAccountId}, ${representation}, ${envelopeDigest}, ${payloadDigest}, ${signingPublicKey},
          ${JSON.stringify(evidence.document)}::jsonb, ${JSON.stringify(evidence.data)}::jsonb,
          ${JSON.stringify(evidence.log)}::jsonb, ${outcome},
          ${outcome === "accepted" ? new Date(now * 1000) : null})
        ON CONFLICT (sender_did, message_id) DO NOTHING
        RETURNING payload_digest
      `;
      if (inserted.length) {
        if (outcome === "accepted") {
          await tx`
            INSERT INTO delivery_work (sender_did, message_id, state)
            VALUES (${payload.from}, ${payload.message_id}, 'accepted')
          `;
        }
        return outcome;
      }
      const winner = await tx<{ payload_digest: Uint8Array }[]>`
        SELECT payload_digest FROM received_envelopes
        WHERE sender_did = ${payload.from} AND message_id = ${payload.message_id}
      `;
      return winner[0] && Buffer.from(winner[0].payload_digest).equals(Buffer.from(payloadDigest)) ? "duplicate" : "conflict";
    });
  }
}
