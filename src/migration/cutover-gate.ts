import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { cidForCbor } from "@atproto/common";
import { def, validateOperationLog, type ExportedOp } from "@did-plc/lib";
import type { SQL } from "bun";
import type { HailDidResolver } from "../plc/resolver.js";
import { parseJsonWithoutDuplicateKeys } from "../discovery/strict-json.js";
import { validateTransferManifest } from "./transfer.js";
import { verifyMonitorAttestation, type SignedMonitorAttestation } from "./monitor-attestation.js";

export interface IndependentPlcObserver {
  origin: string;
  resolver: HailDidResolver;
  audit(did: string): Promise<readonly ExportedOp[]>;
}

export interface CutoverAssessment {
  eligible: boolean;
  operationCid: string;
  firstSeenAt: Date;
  earliestEligibleAt: Date;
}

export class PortableCutoverGate {
  constructor(
    private readonly sql: SQL,
    private readonly observers: readonly [IndependentPlcObserver, IndependentPlcObserver],
    private readonly now: () => Date = () => new Date(),
  ) {}

  async assess(transferId: string, signedMonitor?: SignedMonitorAttestation): Promise<CutoverAssessment> {
    if (!signedMonitor) throw new Error("Public cutover requires a signed independent monitor attestation");
    const imports = await this.sql<{ did: string; state: string; manifest_bytes: Uint8Array;
      signed_plc_operation_bytes: Uint8Array | null }[]>`
      SELECT did, state, manifest_bytes, signed_plc_operation_bytes
      FROM pending_migration_imports WHERE transfer_id = ${transferId}
    `;
    const pending = imports[0];
    if (!pending || pending.state !== "staged" || !pending.signed_plc_operation_bytes) {
      throw new Error("Cutover requires a staged inactive user-signed PLC update");
    }
    const manifest = validateTransferManifest(pending.manifest_bytes);
    const signedOperation = def.operation.parse(parseJsonWithoutDuplicateKeys(
      new TextDecoder("utf-8", { fatal: true }).decode(pending.signed_plc_operation_bytes)));
    const expectedCid = (await cidForCbor(signedOperation)).toString();
    if (manifest.did !== pending.did || manifest.transferId !== transferId) throw new Error("Cutover import correlation failed");
    const custody = manifest.tables.portable_custody_evidence[0]!;
    if (custody.monitor_verification_mode !== "independent") {
      throw new Error("Public cutover requires independent monitor custody evidence");
    }
    const now = this.now();
    const report = await verifyMonitorAttestation(signedMonitor, custody.monitor_public_key as string,
      Math.floor(now.getTime() / 1000));
    if (report.did !== manifest.did || report.transfer_id !== transferId ||
      report.monitor_origin !== custody.monitor_origin) throw new Error("Independent monitor covers another transfer");
    if (this.observers[0].origin === this.observers[1].origin ||
      this.observers.some((observer) => !canonicalMirrorOrigin(observer.origin))) {
      throw new Error("Cutover requires two distinct HTTPS PLC read origins");
    }
    const observations = await Promise.all(this.observers.map(async (observer) => {
      const [resolved, audit] = await Promise.all([
        observer.resolver.resolve(manifest.did), observer.audit(manifest.did),
      ]);
      const log = resolved.evidence.log.map((op) => def.compatibleOpOrTombstone.parse(op));
      const validated = await validateOperationLog(manifest.did, log);
      if (!validated || !isDeepStrictEqual(validated, resolved.evidence.data) || !log.length) {
        throw new Error("Mirror did not return a validated matching PLC operation log");
      }
      const operationCid = (await cidForCbor(log[log.length - 1])).toString();
      const lastAudit = audit[audit.length - 1];
      if (!lastAudit || lastAudit.cid !== operationCid || lastAudit.did !== manifest.did || lastAudit.nullified) {
        throw new Error("Mirror audit does not confirm the current non-nullified operation");
      }
      const data = validated as { rotationKeys: string[]; alsoKnownAs: string[] };
      const recorded = manifest.tables.plc_operation_evidence.at(-1)?.expected_state;
      const before = (typeof recorded === "string" ? parseJsonWithoutDuplicateKeys(recorded) : recorded) as
        { alsoKnownAs?: unknown } | undefined;
      if (resolved.did !== manifest.did || resolved.serviceBase !== manifest.destinationServiceBase ||
        resolved.messagingDidKey !== manifest.destinationMessagingPublicKey ||
        resolved.identityDidKey !== custody.user_identity_public_key ||
        data.rotationKeys[0] !== custody.user_recovery_public_key ||
        !data.rotationKeys.slice(1).includes(manifest.destinationRotationPublicKey) ||
        data.rotationKeys.some((key) => manifest.tables.account_keys.some((entry) =>
          entry.role === "plc-rotation" && entry.public_key === key)) ||
        !before || !isDeepStrictEqual(data.alsoKnownAs, before.alsoKnownAs)) {
        throw new Error("Mirror does not confirm the exact portable destination state");
      }
      return operationCid;
    }));
    if (observations[0] !== observations[1] || report.operation_cid !== observations[0] ||
      observations[0] !== expectedCid) {
      throw new Error("Cutover witnesses disagree on the current PLC operation");
    }
    const operationCid = observations[0]!;
    const attestationDigest = new Uint8Array(createHash("sha256").update(signedMonitor.payloadBytes).digest());
    return this.sql.begin(async (tx): Promise<CutoverAssessment> => {
      const rows = await tx<{ operation_cid: string; first_seen_at: Date }[]>`
        SELECT operation_cid, first_seen_at FROM portable_cutover_observations
        WHERE transfer_id = ${transferId} FOR UPDATE
      `;
      const existing = rows[0];
      if (existing && existing.operation_cid !== operationCid) {
        throw new Error("PLC operation changed during the user-authorized cutover");
      }
      const firstSeen = existing?.first_seen_at ?? now;
      if (report.coverage_since > Math.floor(firstSeen.getTime() / 1000)) {
        throw new Error("Independent monitoring coverage has a gap in the cutover window");
      }
      // stageImport already checked the exact operation against the user's index-zero PLC key.
      // A lower-priority-signed operation cannot be staged through that path.
      const earliest = firstSeen;
      const eligible = true;
      await tx`
        INSERT INTO portable_cutover_observations
          (transfer_id, did, operation_cid, first_seen_at, last_seen_at,
            mirror_origins, monitor_attestation_digest, state, assessment_profile)
         VALUES (${transferId}, ${manifest.did}, ${operationCid}, ${firstSeen}, ${now},
           ${JSON.stringify(this.observers.map((observer) => observer.origin))}::jsonb,
           ${attestationDigest}, 'eligible', 'public')
         ON CONFLICT (transfer_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at,
           mirror_origins = EXCLUDED.mirror_origins,
           monitor_attestation_digest = EXCLUDED.monitor_attestation_digest,
           state = EXCLUDED.state
         WHERE portable_cutover_observations.assessment_profile = 'public'
      `;
      return { eligible, operationCid, firstSeenAt: firstSeen, earliestEligibleAt: earliest };
    });
  }
}

function canonicalMirrorOrigin(input: string): boolean {
  try {
    const url = new URL(input);
    return url.protocol === "https:" && url.href === url.origin + "/" && !url.username && !url.password;
  } catch { return false; }
}
