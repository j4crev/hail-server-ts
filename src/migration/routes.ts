import type { Hono } from "hono";
import type { TransferInvitationReceiver } from "./invitation-receiver.js";
import type { TransferAddressReservation } from "./address-selection.js";
import type { MigrationFenceService } from "./fence.js";
import type { TransferFinalRequestPublisher } from "./final-request-publisher.js";
import type { TransferGrantSubmission } from "./grant-submission.js";
import type { TransferRateLimit } from "./rate-limit.js";
import type { TransferCancellationService } from "./cancellation.js";
import type { TransferCancellationReceiver } from "./cancellation-receiver.js";
import { boundedTransferBody, parseInvitationWire, parseFinalRequestWire,
  parseRequestWire, parseCancellationWire, requestWire,
  TRANSFER_MEDIA_TYPE } from "./wire.js";

export function registerTransferRoutes(app: Hono, receiver: TransferInvitationReceiver,
  reservations?: TransferAddressReservation, fence?: MigrationFenceService,
  publisher?: Pick<TransferFinalRequestPublisher, "publish">,
  grantSubmission?: TransferGrantSubmission, rateLimit?: TransferRateLimit,
  cancellation?: TransferCancellationService,
  cancellationReceiver?: TransferCancellationReceiver): void {
  let windowStarted = Date.now();
  let requests = 0;
  app.post("/.well-known/hail/transfers/invitations", async (context) => {
    if (rateLimit && !await rateLimit.admit("invitation")) return new Response(null, { status: 429 });
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
  if (grantSubmission) app.post("/hail/transfers/grants", async (context) => {
    if (rateLimit && !await rateLimit.admit("grant")) return new Response(null, { status: 429 });
    if (context.req.header("content-type") !== TRANSFER_MEDIA_TYPE ||
      context.req.header("content-encoding") !== undefined) return new Response(null, { status: 415 });
    try {
      const signed = parseRequestWire(await boundedTransferBody(context.req.raw.body,
        context.req.header("content-length") ?? null));
      const offer = await grantSubmission.submit(signed);
      if (!offer) return new Response(null, { status: 202, headers: { "Cache-Control": "no-store" } });
      return new Response(Uint8Array.from(requestWire(offer)), { status: 200,
        headers: { "Content-Type": TRANSFER_MEDIA_TYPE, "Cache-Control": "no-store" } });
    } catch (error) {
      return new Response(null, { status: error instanceof Error && error.message.includes("rate limited") ? 429 : 400,
        headers: { "Cache-Control": "no-store" } });
    }
  });
  if (reservations && publisher) app.post("/.well-known/hail/transfers/reservations", async (context) => {
    if (rateLimit && !await rateLimit.admit("reservation")) return new Response(null, { status: 429 });
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
      return new Response(null, { status: error instanceof Error && error.message === "Address not available" ? 409 :
        error instanceof Error && error.message.includes("rate limited") ? 429 : 400,
        headers: { "Cache-Control": "no-store" } });
    }
  });
  if (fence) app.post("/hail/transfers/requests", async (context) => {
    if (rateLimit && !await rateLimit.admit("request")) return new Response(null, { status: 429 });
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
  if (cancellation) app.post("/hail/transfers/cancellations", async (context) => {
    if (rateLimit && !await rateLimit.admit("grant")) return new Response(null, { status: 429 });
    if (context.req.header("content-type") !== TRANSFER_MEDIA_TYPE ||
      context.req.header("content-encoding") !== undefined) return new Response(null, { status: 415 });
    try {
      const signed = parseRequestWire(await boundedTransferBody(context.req.raw.body,
        context.req.header("content-length") ?? null));
      const receipt = await cancellation.cancel(signed);
      return new Response(Uint8Array.from(requestWire(receipt)), { status: 200,
        headers: { "Content-Type": TRANSFER_MEDIA_TYPE, "Cache-Control": "no-store" } });
    } catch { return new Response(null, { status: 400, headers: { "Cache-Control": "no-store" } }); }
  });
  if (cancellationReceiver) app.post("/.well-known/hail/transfers/cancellations", async (context) => {
    if (rateLimit && !await rateLimit.admit("invitation")) return new Response(null, { status: 429 });
    if (context.req.header("content-type") !== TRANSFER_MEDIA_TYPE ||
      context.req.header("content-encoding") !== undefined) return new Response(null, { status: 415 });
    try {
      const { cancellation: signed, receipt } = parseCancellationWire(await boundedTransferBody(
        context.req.raw.body, context.req.header("content-length") ?? null));
      await cancellationReceiver.receive(signed, receipt);
      return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
    } catch { return new Response(null, { status: 400, headers: { "Cache-Control": "no-store" } }); }
  });
}
