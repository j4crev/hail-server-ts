import { decodeDeterministic, encodeDeterministic, type HailValue } from "@hailproto/codec";
import { ed25519PublicKeyFromDidKey } from "../identity/did-key.js";

const CONTEXT = new TextEncoder().encode("hail.independent-plc-monitor.v1\0");

export interface PlcMonitorAttestation {
  type: "hail.plc-monitor-attestation";
  version: 1;
  did: string;
  transfer_id: string;
  operation_cid: string;
  monitor_origin: string;
  coverage_since: number;
  observed_at: number;
}

export interface SignedMonitorAttestation {
  payloadBytes: Uint8Array;
  signature: Uint8Array;
}

function checked(value: unknown): asserts value is PlcMonitorAttestation {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid PLC monitor attestation");
  const row = value as Record<string, unknown>;
  const fields = ["type", "version", "did", "transfer_id", "operation_cid", "monitor_origin", "coverage_since", "observed_at"];
  if (Object.keys(row).length !== fields.length || fields.some((field) => !Object.hasOwn(row, field)) ||
    row.type !== "hail.plc-monitor-attestation" || row.version !== 1 ||
    typeof row.did !== "string" || !/^did:plc:[a-z2-7]{24}$/.test(row.did) ||
    typeof row.transfer_id !== "string" || !/^[0-9a-f-]{36}$/.test(row.transfer_id) ||
    typeof row.operation_cid !== "string" || !/^b[a-z2-7]+$/.test(row.operation_cid) ||
    typeof row.monitor_origin !== "string" || typeof row.coverage_since !== "number" ||
    !Number.isSafeInteger(row.coverage_since) || typeof row.observed_at !== "number" ||
    !Number.isSafeInteger(row.observed_at) || row.coverage_since > row.observed_at) {
    throw new Error("Invalid PLC monitor attestation fields");
  }
  const url = new URL(row.monitor_origin);
  if (url.protocol !== "https:" || url.href !== url.origin + "/" || url.username || url.password) {
    throw new Error("Monitor origin must be canonical HTTPS");
  }
}

function signatureInput(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(CONTEXT.length + bytes.length);
  result.set(CONTEXT);
  result.set(bytes, CONTEXT.length);
  return result;
}

// The independent monitor signs this outside the provider's administrative domain.
export async function signMonitorAttestation(payload: PlcMonitorAttestation, key: CryptoKey): Promise<SignedMonitorAttestation> {
  checked(payload);
  const payloadBytes = encodeDeterministic(payload as unknown as HailValue);
  return { payloadBytes, signature: new Uint8Array(await crypto.subtle.sign("Ed25519", key, signatureInput(payloadBytes))) };
}

export async function verifyMonitorAttestation(signed: SignedMonitorAttestation,
  publicKey: string, now: number): Promise<PlcMonitorAttestation> {
  if (signed.payloadBytes.length < 1 || signed.payloadBytes.length > 4096 || signed.signature.length !== 64) {
    throw new Error("Monitor attestation representation exceeds its limit");
  }
  const payload: unknown = decodeDeterministic(signed.payloadBytes);
  checked(payload);
  if (payload.observed_at > now + 300 || now - payload.observed_at > 86_400 ||
    !Buffer.from(encodeDeterministic(payload as unknown as HailValue)).equals(Buffer.from(signed.payloadBytes))) {
    throw new Error("Monitor attestation is stale or non-deterministic");
  }
  if (!await crypto.subtle.verify("Ed25519", await ed25519PublicKeyFromDidKey(publicKey),
    Uint8Array.from(signed.signature), signatureInput(signed.payloadBytes))) {
    throw new Error("Monitor attestation signature is invalid");
  }
  return payload;
}
