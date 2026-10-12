import { isDeepStrictEqual } from "node:util";
import { cidForCbor } from "@atproto/common";
import { assureValidNextOp, def, validateOperationLog, type IndexedOperation } from "@did-plc/lib";
import type { PlcResolutionEvidence } from "./resolver.js";
import { createHash } from "node:crypto";
import { DEFAULT_HAIL_RESOURCE_LIMITS, encodeBase64Url, encodeDeterministic, type HailValue } from "@hailproto/codec";
import type { DocumentData } from "@did-plc/lib";

export const PUBLIC_EVIDENCE_LIMITS = { ...DEFAULT_HAIL_RESOURCE_LIMITS,
  maximumBytes: 8 * 1024 * 1024, maximumItems: 500_000,
  maximumTextBytes: 1_048_576, maximumByteStringLength: 1_048_576 };
export const evidenceHash = (bytes: Uint8Array) => new Uint8Array(createHash("sha256").update(bytes).digest());
export const encodePublicEvidence = (value: HailValue) => encodeDeterministic(value, PUBLIC_EVIDENCE_LIMITS);

export function plcStateDigest(state: DocumentData): string {
  return encodeBase64Url(new Uint8Array(createHash("sha256").update(encodeDeterministic(state as unknown as HailValue)).digest()));
}

// ponytail: complete histories capped at 1,000; add verified pagination if larger histories are needed.
export async function validatePlcReadEvidence(did: string, evidence: PlcResolutionEvidence, rawAudit: readonly unknown[]) {
  if (!/^did:plc:[a-z2-7]{24}$/.test(did) || !evidence.log.length || evidence.log.length > 1000 ||
    !rawAudit.length || rawAudit.length > 1000) throw new Error("Mirror audit/log is incomplete or exceeds the verification limit");
  const log = evidence.log.map(operation => def.compatibleOpOrTombstone.parse(operation));
  const state = await validateOperationLog(did, log);
  if (!state || !isDeepStrictEqual(state, evidence.data)) throw new Error("Mirror log and full PLC state disagree");
  const audit = rawAudit.map(entry => def.exportedOp.parse(entry));
  const history: IndexedOperation[] = [], seen = new Set<string>();
  let previousTime = -Infinity;
  for (const entry of audit) {
    const cid = await cidForCbor(entry.operation), createdAt = new Date(entry.createdAt);
    if (entry.did !== did || cid.toString() !== entry.cid || seen.has(entry.cid) ||
      !Number.isFinite(createdAt.getTime()) || createdAt.getTime() < previousTime) {
      throw new Error("Mirror audit DID, CID, ordering or operation bytes are invalid");
    }
    const result = await assureValidNextOp(did, history.filter(operation => !operation.nullified), entry.operation, createdAt);
    for (const nullified of result.nullified) {
      const prior = history.find(operation => operation.cid.equals(nullified));
      if (!prior) throw new Error("Mirror audit recovery refers to missing history");
      prior.nullified = true;
    }
    history.push({ did, cid, operation: entry.operation, createdAt, nullified: false });
    seen.add(entry.cid); previousTime = createdAt.getTime();
  }
  if (history.some((operation, index) => operation.nullified !== audit[index]!.nullified) ||
    !isDeepStrictEqual(history.filter(operation => !operation.nullified).map(operation => operation.operation), log)) {
    throw new Error("Mirror audit nullification or complete canonical chain disagrees with the PLC log");
  }
  return { state, log, audit, operationCid: (await cidForCbor(log.at(-1)!)).toString() };
}
