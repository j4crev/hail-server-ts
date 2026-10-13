import { isDeepStrictEqual } from "node:util";
import { cidForCbor } from "@atproto/common";
import { def, validateOperationLog } from "@did-plc/lib";
import { plcStateDigest, validatePlcReadEvidence } from "../plc/read-evidence.js";
import type { SQL } from "bun";
import { canonicalPlcReadOrigin, type IndependentPlcObserver } from "../plc/observers.js";
export { createIndependentPlcObserver, type IndependentPlcObserver } from "../plc/observers.js";
import { parseJsonWithoutDuplicateKeys } from "../discovery/strict-json.js";
import { validateTransferManifest } from "./transfer.js";
import { verifyMonitorAttestation, type SignedMonitorAttestation } from "./monitor-attestation.js";
import { encodePublicCutoverEvidence, evidenceHash, requirePublicCutoverEvidence } from "./public-cutover-evidence.js";
import { encode as encodeDagCbor } from "@ipld/dag-cbor";
import type { HailValue } from "@hailproto/codec";
import { PLC_READ_EVIDENCE_POLICY_VERSION } from "../identity/managed-profile.js";

export interface CutoverAssessment {
  eligible: boolean;
  operationCid: string;
  firstSeenAt: Date;
  earliestEligibleAt: Date;
  evidenceDigest?: Uint8Array;
}

export class PortableCutoverGate {
  constructor(
    private readonly sql: SQL,
    private readonly observers: readonly [IndependentPlcObserver, IndependentPlcObserver],
    private readonly now: () => Date = () => new Date(),
    private readonly providerOperators: readonly string[] = [],
  ) {}

  async assess(transferId: string, signedMonitor?: SignedMonitorAttestation): Promise<CutoverAssessment> {
    if (!signedMonitor) throw new Error("Public cutover requires a signed independent monitor attestation");
    const monitor = { payloadBytes: Uint8Array.from(signedMonitor.payloadBytes), signature: Uint8Array.from(signedMonitor.signature) };
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
    if (!manifest.tables.plc_operation_evidence.length || manifest.tables.plc_operation_evidence.some(entry => entry.registry_origin !== "https://plc.directory")) {
      throw new Error("Public cutover requires canonical public PLC registration evidence; private records cannot be relabeled");
    }
    const now = this.now();
    const report = await verifyMonitorAttestation(monitor, custody.monitor_public_key as string,
      Math.floor(now.getTime() / 1000), 300);
    if (report.version !== 2) throw new Error("Public cutover requires a reviewed bootstrap v2 monitor attestation");
    if (report.did !== manifest.did || report.transfer_id !== transferId ||
      report.monitor_origin !== custody.monitor_origin) throw new Error("Independent monitor covers another transfer");
    const providerHosts = [manifest.sourceServiceBase, manifest.destinationServiceBase].map(base => new URL(base).hostname);
    const identifier = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value);
    if (providerHosts.includes(new URL(report.monitor_origin).hostname) ||
      this.providerOperators.length < 1 || this.providerOperators.length > 2 || !this.providerOperators.every(identifier) ||
      this.observers.some(observer => !canonicalPlcReadOrigin(observer.origin) || !identifier(observer.operator) ||
        this.providerOperators.includes(observer.operator) || providerHosts.includes(new URL(observer.origin).hostname)) ||
      this.observers[0].operator === this.observers[1].operator ||
      new URL(this.observers[0].origin).hostname === new URL(this.observers[1].origin).hostname) {
      throw new Error("Cutover requires two independently configured HTTPS PLC readers and provider operator declarations");
    }
    const observations = await Promise.all(this.observers.map(async (observer) => {
      const [resolved, audit] = await Promise.all([
        observer.resolver.resolve(manifest.did), observer.audit(manifest.did),
      ]);
      const checked = await validatePlcReadEvidence(manifest.did, resolved.evidence, audit);
      const cids = await Promise.all(checked.log.map(async operation => (await cidForCbor(operation)).toString()));
      const checkpoint = cids.indexOf(report.bootstrap_cid!);
      const bootstrapState = checkpoint < 0 || checkpoint === checked.log.length - 1 ? null :
        await validateOperationLog(manifest.did, checked.log.slice(0, checkpoint + 1));
      if (!bootstrapState || plcStateDigest(bootstrapState) !== report.bootstrap_state_digest) {
        throw new Error("Mirror does not confirm the reviewed monitor bootstrap checkpoint");
      }
      const { operationCid, state: validated } = checked;
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
      return { checked, document: structuredClone(resolved.evidence.document), bootstrapState };
    }));
    if (!isDeepStrictEqual(observations[0]!.checked, observations[1]!.checked) || report.operation_cid !== observations[0]!.checked.operationCid ||
      observations[0]!.checked.operationCid !== expectedCid) {
      throw new Error("Cutover witnesses disagree on the current PLC operation");
    }
    const operationCid = observations[0]!.checked.operationCid;
    const attestationDigest = evidenceHash(monitor.payloadBytes), manifestDigest = evidenceHash(pending.manifest_bytes);
    const verifiedAt = this.now();
    if (verifiedAt.getTime() < now.getTime()) throw new Error("PLC verification clock moved backwards");
    await verifyMonitorAttestation(monitor, custody.monitor_public_key as string, Math.floor(verifiedAt.getTime() / 1000), 300);
    return this.sql.begin(async (tx): Promise<CutoverAssessment> => {
      // Same import-first order as activation/invalidation. A read paused across
      // an import change cannot publish evidence or eligible state afterwards.
      const current = (await tx<{ state: string; did: string; manifest_bytes: Uint8Array; signed_plc_operation_bytes: Uint8Array }[]>`
        SELECT state, did, manifest_bytes, signed_plc_operation_bytes FROM pending_migration_imports
        WHERE transfer_id = ${transferId} FOR UPDATE`)[0];
      if (!current || current.state !== "staged" || current.did !== pending.did ||
        !Buffer.from(current.manifest_bytes).equals(Buffer.from(pending.manifest_bytes)) ||
        !Buffer.from(current.signed_plc_operation_bytes).equals(Buffer.from(pending.signed_plc_operation_bytes!))) {
        throw new Error("Cutover import changed while PLC evidence was being verified");
      }
      const rows = await tx<{ operation_cid: string; first_seen_at: Date; assessment_profile: string }[]>`
        SELECT operation_cid, first_seen_at, assessment_profile FROM portable_cutover_observations
        WHERE transfer_id = ${transferId} FOR UPDATE
      `;
      const existing = rows[0];
      if (existing && existing.assessment_profile !== "public") throw new Error("Cutover observation conflicts with the public PLC trust profile");
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
      // ponytail: full bundles duplicate repeated read data; share content-addressed blobs if storage volume warrants it.
      const bundleBytes = encodePublicCutoverEvidence({ type: "hail.public-cutover-evidence", version: 1,
        policy: PLC_READ_EVIDENCE_POLICY_VERSION, registry_origin: "https://plc.directory", transfer_id: transferId,
        did: manifest.did, account_id: manifest.accountId, manifest_digest: manifestDigest,
        operation_cid: operationCid, signed_operation_bytes: pending.signed_plc_operation_bytes!,
        first_seen_at: firstSeen.toISOString(), read_started_at: now.toISOString(), verified_at: verifiedAt.toISOString(),
        provider_operators: [...this.providerOperators],
        monitor: { public_key: custody.monitor_public_key as string, payload: monitor.payloadBytes, signature: monitor.signature },
        bootstrap: { operation_cid: report.bootstrap_cid!, state_digest: report.bootstrap_state_digest!, state: observations[0]!.bootstrapState },
        witnesses: observations.map((observation, index) => ({ origin: this.observers[index]!.origin,
          operator: this.observers[index]!.operator!, document: observation.document,
          state: observation.checked.state, log: observation.checked.log, audit: observation.checked.audit,
          signed_operations: observation.checked.audit.map(entry => ({ cid: entry.cid, dag_cbor: new Uint8Array(encodeDagCbor(entry.operation)) })) })),
      } as unknown as HailValue);
      const evidenceDigest = evidenceHash(bundleBytes);
      await tx`INSERT INTO public_cutover_evidence
        (transfer_id, evidence_digest, did, operation_cid, manifest_digest, signed_operation_bytes,
          monitor_attestation_digest, verified_at, bundle_bytes, record_version, read_evidence_policy_version)
        VALUES (${transferId}, ${evidenceDigest}, ${manifest.did}, ${operationCid}, ${manifestDigest},
          ${pending.signed_plc_operation_bytes!}, ${attestationDigest}, ${verifiedAt}, ${bundleBytes}, 1,
          ${PLC_READ_EVIDENCE_POLICY_VERSION})
        ON CONFLICT (transfer_id, evidence_digest) DO NOTHING`;
      const retained = (await tx<{ bundle_bytes: Uint8Array }[]>`SELECT bundle_bytes FROM public_cutover_evidence
        WHERE transfer_id=${transferId} AND evidence_digest=${evidenceDigest}`)[0];
      if (!retained || !Buffer.from(retained.bundle_bytes).equals(Buffer.from(bundleBytes))) throw new Error("Retained public cutover evidence conflicts");
      const selected = (await tx<{ activated_at: Date | null }[]>`SELECT activated_at FROM public_cutover_evidence_selection
        WHERE transfer_id=${transferId} FOR UPDATE`)[0];
      if (selected?.activated_at) throw new Error("Activated evidence cannot be selected for a fresh cutover");
      await tx`INSERT INTO public_cutover_evidence_selection (transfer_id, evidence_digest) VALUES (${transferId},${evidenceDigest})
        ON CONFLICT (transfer_id) DO UPDATE SET evidence_digest=EXCLUDED.evidence_digest`;
      const saved = await requirePublicCutoverEvidence(tx, { transferId, did: manifest.did, manifestDigest,
        operationBytes: pending.signed_plc_operation_bytes!, monitorPublicKey: custody.monitor_public_key as string,
        digest: evidenceDigest, activatedAt: null });
      if (saved.verified_at.getTime() !== verifiedAt.getTime()) throw new Error("Retained public evidence verification time conflicts");
      await tx`
        INSERT INTO portable_cutover_observations
          (transfer_id, did, operation_cid, first_seen_at, last_seen_at,
            mirror_origins, monitor_attestation_digest, state, assessment_profile)
          VALUES (${transferId}, ${manifest.did}, ${operationCid}, ${firstSeen}, ${verifiedAt},
           ${JSON.stringify(this.observers.map((observer) => observer.origin))}::jsonb,
           ${attestationDigest}, 'eligible', 'public')
         ON CONFLICT (transfer_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at,
           mirror_origins = EXCLUDED.mirror_origins,
           monitor_attestation_digest = EXCLUDED.monitor_attestation_digest,
           state = EXCLUDED.state
         WHERE portable_cutover_observations.assessment_profile = 'public'
      `;
      return { eligible, operationCid, firstSeenAt: firstSeen, earliestEligibleAt: earliest, evidenceDigest };
    });
  }
}
