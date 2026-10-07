import { encodeBase64Url, HailCodecError, inspectSignedPayload } from "@hailproto/codec";
import type { Context, Hono } from "hono";
import { isCoseSign1MediaType } from "../http/media-type.js";
import { GrantConflictError, type GrantRepository } from "../grants/repository.js";
import { UserGrantError, type GrantService } from "../grants/service.js";
import type { AccountApiRepository } from "./repository.js";

const GRANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES = 262_144;

async function body(request: Request): Promise<Uint8Array | null> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BYTES)) return null;
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      length += next.value.length;
      if (length > MAX_BYTES) { await reader.cancel(); return null; }
      chunks.push(next.value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

export function registerAccountApiRoutes(app: Hono, accounts: AccountApiRepository,
  grants: GrantRepository, service: GrantService, provider: string): void {
  let window = Date.now();
  let requests = 0;
  const handle = async (context: Context, grantId: string | null) => {
    context.header("Cache-Control", "no-store");
    context.header("Vary", "Authorization");
    const problem = (status: 400 | 401 | 403 | 404 | 405 | 409 | 413 | 415 | 429 | 503) => {
      const title = ({ 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
        405: "Method Not Allowed", 409: "Conflict", 413: "Content Too Large", 415: "Unsupported Media Type",
        429: "Too Many Requests", 503: "Service Unavailable" } as const)[status];
      context.header("Content-Type", "application/problem+json");
      return context.json({ type: "about:blank", title, status }, status, { "Content-Type": "application/problem+json" });
    };
    if (Date.now() - window >= 60_000) { window = Date.now(); requests = 0; }
    if (++requests > 120) { context.header("Retry-After", "60"); return problem(429); }
    try {
      const session = await accounts.authenticate(context.req.header("Authorization"));
      if (!session) { context.header("WWW-Authenticate", 'Bearer realm="hailp-account"'); return problem(401); }
      if (new URL(context.req.url).search) return problem(400);
      const method = context.req.method;
      const scope = grantId === null ? "account:read" : method === "PUT" ? "grants:write" : "grants:read";
      if (!session.scopes.includes(scope)) return problem(403);
      if (method !== "GET" && !(grantId !== null && method === "PUT")) {
        context.header("Allow", grantId === null ? "GET" : "GET, PUT");
        return problem(405);
      }
      if (grantId === null) return context.json(await accounts.describe(session, provider));
      if (!GRANT_ID.test(grantId)) return problem(400);
      const current = await grants.findCurrentByGrantId(grantId);
      if (method === "GET") {
        const owned = current?.localAccountId === session.account_id ? current :
          await grants.findReceivedForSender(grantId, session.did);
        if (!owned || owned.localAccountId !== session.account_id) return problem(404);
        const digest = encodeBase64Url(owned.digest);
        context.header("ETag", `"${digest}"`);
        return context.json({ type: "hailp.grant", version: 1, localRole: owned.localRole,
          digest, cose: encodeBase64Url(owned.representation) });
      }
      if (session.migration_state) return problem(409);
      if (current && (current.localAccountId !== session.account_id || current.localRole !== "grantor")) return problem(404);
      if (!isCoseSign1MediaType(context.req.header("Content-Type") ?? null) || context.req.header("Content-Encoding") !== undefined) {
        return problem(415);
      }
      const representation = await body(context.req.raw);
      if (representation === null) return problem(413);
      const payload = inspectSignedPayload("hail.grant", representation).payload;
      if (payload.grant_id !== grantId) return problem(400);
      const saved = await service.acceptUserSignedGrant(session.canonical_address,
        payload.consent_context.grantee_address, representation);
      context.header("ETag", `"${encodeBase64Url(saved.digest)}"`);
      return context.json({ grantId, revision: saved.payload.revision, status: saved.payload.status,
        digest: encodeBase64Url(saved.digest), publication: "durable" });
    } catch (error) {
      if (error instanceof UserGrantError) return problem(error.status);
      if (error instanceof HailCodecError) return problem(400);
      if (error instanceof GrantConflictError || error instanceof Error && "code" in error && error.code === "55000") {
        return problem(409);
      }
      context.header("Retry-After", "30");
      return problem(503);
    }
  };
  app.all("/api/v1/account", context => handle(context, null));
  app.all("/api/v1/account/grants/:grantId", context => handle(context, context.req.param("grantId")));
}
