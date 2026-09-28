import { createHash } from "node:crypto";
import { encodeBase64Url, inspectSignedPayload } from "@hailproto/codec";
import { loadConfig } from "../config.js";
import { ProviderDatabase } from "../db/database.js";
import { SafeHttpsTransport } from "../discovery/safe-fetch.js";
import { COSE_SIGN1_MEDIA_TYPE } from "../discovery/routes.js";
import { EnvelopeRepository } from "../envelopes/repository.js";
import { createPlcDirectoryClient } from "../plc/client.js";
import { PlcHailDidResolver } from "../plc/resolver.js";
import { DeliveryStatusReceiver } from "../delivery/status-receiver.js";
import { OnboardingRepository } from "../onboarding/repository.js";

const [senderDid, messageId] = Bun.argv.slice(2);
if (!senderDid || !messageId) throw new Error("Usage: bun run envelope:submit -- <sender-did> <message-id>");

async function receipt(response: Response, maximum: number): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum)) {
    await response.body?.cancel();
    throw new Error("Envelope receipt exceeds its size limit");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > maximum) { await reader.cancel(); throw new Error("Envelope receipt exceeds its size limit"); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

const database = new ProviderDatabase(loadConfig().databaseUrl);
try {
  await database.migrate();
  const representation = await new EnvelopeRepository(database.sql).sent(senderDid, messageId);
  if (!representation) throw new Error("Sent envelope is not stored");
  const envelope = inspectSignedPayload("hail.envelope", representation).payload;
  if (envelope.from !== senderDid || envelope.message_id !== messageId) throw new Error("Stored envelope does not match lookup");
  const resolver = new PlcHailDidResolver(createPlcDirectoryClient(loadConfig().plcDirectoryUrl));
  const destination = await resolver.resolve(envelope.to);
  const url = new URL(`${destination.serviceBase}/envelopes`);
  const transport = new SafeHttpsTransport();
  await transport.validateTarget(url);
  const response = await transport.fetch(new Request(url, {
    method: "POST", headers: { "Content-Type": COSE_SIGN1_MEDIA_TYPE, "Accept-Encoding": "identity", "Cache-Control": "no-store" },
    body: Uint8Array.from(representation).buffer, redirect: "manual", signal: AbortSignal.timeout(15_000),
  }));
  if (response.headers.get("content-encoding") || ![200, 202].includes(response.status)) {
    await response.body?.cancel();
    throw new Error(`Envelope submission returned unexpected HTTP ${response.status}; retry using the same message ID after checking the recipient`);
  }
  const digest = encodeBase64Url(createHash("sha256").update(inspectSignedPayload("hail.envelope", representation).payloadBytes).digest());
  if (response.status === 200) {
    if (response.headers.get("content-type") !== COSE_SIGN1_MEDIA_TYPE) throw new Error("Signed status media type is invalid");
    const cose = await receipt(response, 16_384);
    const outcome = await new DeliveryStatusReceiver(database.sql, new OnboardingRepository(database.sql), resolver,
      loadConfig().hailServiceBase).receive(digest, cose);
    if (outcome !== "acknowledged") throw new Error("Signed status did not authenticate or correlate to the sent envelope");
    const status = inspectSignedPayload("hail.delivery-status", cose).payload;
    console.info(JSON.stringify({ messageId, envelopeDigest: digest, state: status.state, revision: status.revision }, null, 2));
  } else {
    if (response.headers.get("content-type") !== "application/json" ||
      new TextDecoder("utf-8", { fatal: true }).decode(await receipt(response, 1024)) !== '{"outcome":"received"}') {
      throw new Error("Envelope receipt is invalid");
    }
    console.info(JSON.stringify({ messageId, envelopeDigest: digest, outcome: "received", accepted: false }, null, 2));
  }
} finally { await database.close(); }
