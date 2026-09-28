import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import { registerEnvelopeRoutes } from "../src/envelopes/routes.js";
import type { EnvelopeReceiver } from "../src/envelopes/receiver.js";
import { registerDeliveryStatusRoutes } from "../src/delivery/status-routes.js";

function setup(receive = vi.fn<EnvelopeReceiver["receive"]>(async () => "ignored")) {
  const app = new Hono();
  registerEnvelopeRoutes(app, { receive });
  return { app, receive };
}

describe("envelope submission HTTP binding", () => {
  it("returns a generic indeterminate receipt for processed and unprocessed envelopes", async () => {
    for (const result of ["accepted", "ignored", "duplicate", "unauthorized"] as const) {
      const { app, receive } = setup(vi.fn(async () => result));
      const response = await app.request("/hail/envelopes", { method: "POST",
        headers: { "Content-Type": 'application/cose; cose-type="cose-sign1"' },
        body: new Uint8Array([1, 2, 3]) });
      expect(response.status).toBe(202);
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(await response.text()).toBe('{"outcome":"received"}');
      expect(receive).toHaveBeenCalledOnce();
    }
  });

  it("rejects transport failures before invoking protected processing", async () => {
    const { app, receive } = setup();
    expect((await app.request("/hail/envelopes", { method: "GET" })).headers.get("allow")).toBe("POST");
    expect((await app.request("/hail/envelopes", { method: "POST", body: "bad" })).status).toBe(415);
    expect((await app.request("/hail/envelopes", { method: "POST",
      headers: { "Content-Type": 'application/cose; cose-type="cose-sign1"' },
      body: new Uint8Array(16_385) })).status).toBe(413);
    expect(receive).not.toHaveBeenCalled();
  });

  it("returns a signed COSE snapshot only after authenticated acceptance", async () => {
    // Reuse a structurally signed envelope from codec tests rather than forging acceptance
    // from the request's claimed sender fields.
    const { createWebCryptoSigner, signPayload } = await import("@hailproto/codec");
    const key = (await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])) as CryptoKeyPair;
    const sender = `did:plc:${"a".repeat(24)}`;
    const messageId = "01954144-8097-7a9d-a7a8-ef29a823eaf1";
    const representation = await signPayload("hail.envelope", {
      type: "hail.envelope", version: 1, message_id: messageId, from: sender,
      to: `did:plc:${"b".repeat(24)}`, authorization: { type: "grant", grant_id: messageId },
      category: "updates", created_at: 1_790_000_000, expires_at: 1_790_086_400,
      body: { digest: { algorithm: "sha-256", value: new Uint8Array(32) }, size: 1,
        media_type: "application/hail-body+cbor", profile: "spt-1", available_until: 1_793_000_000,
        access: { type: "bearer", token: new Uint8Array(32), expires_at: 1_793_000_000 } },
      reply: { allowed: false },
    }, createWebCryptoSigner(`${sender}#hail-messaging`, key.privateKey));
    const responseApp = new Hono();
    const signer = { signCurrent: vi.fn(async () => new Uint8Array([0xd2, 1, 2])) };
    registerEnvelopeRoutes(responseApp, { receive: vi.fn(async () => "accepted" as const) }, signer);
    const response = await responseApp.request("/hail/envelopes", { method: "POST",
      headers: { "Content-Type": 'application/cose; cose-type="cose-sign1"' }, body: Uint8Array.from(representation) });
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([0xd2, 1, 2]));
    expect(signer.signCurrent).toHaveBeenCalledWith(sender, messageId);
  });
});

describe("terminal status PUT binding", () => {
  it("acknowledges authenticated pushes without a body and keeps unknown state generic", async () => {
    const path = `/hail/deliveries/${"A".repeat(43)}`;
    const app = new Hono();
    const receive = vi.fn(async () => "acknowledged" as const);
    registerDeliveryStatusRoutes(app, { receive });
    const options = { method: "PUT", headers: { "Content-Type": 'application/cose; cose-type="cose-sign1"' },
      body: new Uint8Array([1, 2]) };
    const accepted = await app.request(path, options);
    expect(accepted.status).toBe(204);
    expect(await accepted.text()).toBe("");
    expect(receive).toHaveBeenCalledWith("A".repeat(43), new Uint8Array([1, 2]));
    receive.mockResolvedValueOnce("unknown" as never);
    const generic = await app.request(path, options);
    expect(generic.status).toBe(202);
    expect(await generic.text()).toBe('{"outcome":"received"}');
  });

  it("rejects malformed transport before protected state and advertises PUT", async () => {
    const app = new Hono();
    const receive = vi.fn(async () => "unknown" as const);
    registerDeliveryStatusRoutes(app, { receive });
    const path = `/hail/deliveries/${"A".repeat(43)}`;
    const media = 'application/cose; cose-type="cose-sign1"';
    expect((await app.request(path, { method: "GET" })).headers.get("allow")).toBe("PUT");
    expect((await app.request(path, { method: "PUT", headers: { "Content-Type": "application/json" } })).status).toBe(415);
    expect((await app.request(`${path}=`, { method: "PUT", headers: { "Content-Type": media } })).status).toBe(400);
    expect((await app.request(path, { method: "PUT", headers: { "Content-Type": media },
      body: new Uint8Array(16_385) })).status).toBe(413);
    expect(receive).not.toHaveBeenCalled();
  });
});
