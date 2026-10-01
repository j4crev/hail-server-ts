import type { Hono } from "hono";
import type { TransferInvitationReceiver } from "./invitation-receiver.js";
import type { TransferAddressReservation } from "./address-selection.js";
import type { MigrationFenceService } from "./fence.js";
import type { TransferFinalRequestPublisher } from "./final-request-publisher.js";
import { boundedTransferBody, parseInvitationWire, parseFinalRequestWire,
  parseRequestWire, requestWire,
  TRANSFER_MEDIA_TYPE } from "./wire.js";

export function registerTransferRoutes(app: Hono, receiver: TransferInvitationReceiver,
  reservations?: TransferAddressReservation, fence?: MigrationFenceService,
  publisher?: Pick<TransferFinalRequestPublisher, "publish">): void {
  let windowStarted = Date.now();
  let requests = 0;
  app.post("/.well-known/hail/transfers/invitations", async (context) => {
    if (Date.now() - windowStarted > 60_000) { windowStarted = Date.now(); requests = 0; }
    if (++requests > 60) return new Response(null, { status: 429, headers: { "Cache-Control": "no-store" } });
    if (context.req.header("content-type") !== TRANSFER_MEDIA_TYPE ||
      context.req.header("content-encoding") !== undefined) {
      return new Response(null, { status: 415, headers: { "Cache-Control": "no-store" } });
    }
    try {
      const { grant, invitation } = parseInvitationWire(await boundedTransferBody(
        context.req.raw.body, context.req.header("content-length") ?? null));
      const signedRequest = await receiver.receive(grant, invitation);
      return new Response(Uint8Array.from(requestWire(signedRequest)), { status: 200, headers: {
        "Content-Type": TRANSFER_MEDIA_TYPE, "Cache-Control": "no-store",
      } });
    } catch {
      return new Response(null, { status: 400, headers: { "Cache-Control": "no-store" } });
    }
  });
  if (reservations && publisher) app.post("/.well-known/hail/transfers/reservations", async (context) => {
    if (Date.now() - windowStarted > 60_000) { windowStarted = Date.now(); requests = 0; }
    if (++requests > 60) return new Response(null, { status: 429 });
    if (context.req.header("content-type") !== TRANSFER_MEDIA_TYPE ||
      context.req.header("content-encoding") !== undefined) return new Response(null, { status: 415 });
    try {
      const selection = parseRequestWire(await boundedTransferBody(context.req.raw.body,
        context.req.header("content-length") ?? null));
      const reserved = await reservations.reserve(selection);
      // The reservation survives a failed or ambiguous push; retrying the
      // same signed selection resumes publication without choosing a new name.
      try { await publisher.publish(reserved.prepared.transferId); }
      catch { return new Response(Uint8Array.from(requestWire(reserved.receipt)), { status: 202,
        headers: { "Content-Type": TRANSFER_MEDIA_TYPE, "Cache-Control": "no-store" } }); }
      return new Response(Uint8Array.from(requestWire(reserved.receipt)), { status: 200,
        headers: { "Content-Type": TRANSFER_MEDIA_TYPE, "Cache-Control": "no-store" } });
    } catch (error) {
      return new Response(null, { status: error instanceof Error && error.message === "Address not available" ? 409 : 400,
        headers: { "Cache-Control": "no-store" } });
    }
  });
  if (fence) app.post("/hail/transfers/requests", async (context) => {
    if (context.req.header("content-type") !== TRANSFER_MEDIA_TYPE ||
      context.req.header("content-encoding") !== undefined) return new Response(null, { status: 415 });
    try {
      const { selection, reservation, request } = parseFinalRequestWire(await boundedTransferBody(
        context.req.raw.body, context.req.header("content-length") ?? null));
      if (await fence.previouslyAccepted(request, selection, reservation)) {
        return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
      }
      await fence.begin(request, selection, reservation);
      return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
    } catch { return new Response(null, { status: 400, headers: { "Cache-Control": "no-store" } }); }
  });
}
