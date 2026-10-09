import { encodeBase64Url, HailCodecError, inspectSignedPayload, toDiagnosticJson } from "@hailproto/codec";
import type { Context, Hono } from "hono";
import { isCoseSign1MediaType } from "../http/media-type.js";
import { GrantConflictError, type GrantRepository } from "../grants/repository.js";
import { UserGrantError, type GrantService } from "../grants/service.js";
import { ALL_ACCOUNT_SCOPES, CredentialConflictError, type AccountApiRepository } from "./repository.js";
import type { AccountMessaging } from "./messaging.js";
import { parseJsonWithoutDuplicateKeys } from "../discovery/strict-json.js";

const GRANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BYTES = 262_144;
const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;

export async function accountRequestBytes(request: Request): Promise<Uint8Array | null> {
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
  grants: GrantRepository, service: GrantService, provider: string, messaging?:AccountMessaging): void {
  let window = Date.now();
  let requests = 0;
  const handle = async (context: Context, grantId: string | null, action?: string) => {
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
      const query = new URL(context.req.url).searchParams;
      if (query.size && action !== "list" && action !== "inbox" && action !== "credential") return problem(400);
      const method = context.req.method;
      const scope = action === "send" || action === "resubmit" ? "messages:write" : ["inbox","read","status"].includes(action ?? "") ? "messages:read" : action === "credential" ? "credentials:write" : action === "proposal" || action === "managed-create" || action === "managed-revoke" ? "grants:write" : action === "list" ? "grants:read" :
        grantId === null ? "account:read" : method === "PUT" ? "grants:write" : "grants:read";
      if (!session.scopes.includes(scope)) return problem(403);
      if(["send","resubmit","inbox","read","status"].includes(action ?? "")) {
        if(!messaging)return problem(503);
        if(action==="send"||action==="resubmit") {
          if(method!=="POST")return problem(405);if(session.migration_state)return problem(409);
          if(action==="resubmit") {
            if(!grantId||!GRANT_ID.test(grantId))return problem(400);
            if(!await messaging.status(session,grantId))return problem(404);
            return context.json(await messaging.submit(session.did,grantId));
          }
          if(context.req.header("Content-Type")!=="application/json"||context.req.header("Content-Encoding")!==undefined)return problem(415);
          const bytes=await accountRequestBytes(context.req.raw);if(!bytes)return problem(413);
          const input=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));if(!input||typeof input!=="object"||Array.isArray(input))return problem(400);
          return context.json(await messaging.send(session,input));
        }
        if(method!=="GET")return problem(405);
        if(action==="inbox") {
          if([...query.keys()].some(k=>k!=="after"))return problem(400);
          return context.json(await messaging.inbox(session,query.get("after")));
        }
        const found=action==="read"?await messaging.read(session,context.req.param("sender")!,grantId!):await messaging.status(session,grantId!);
        return found?context.json(found):problem(404);
      }
      if (action === "credential") {
        if (method === "GET") {
          const after = query.get("after");
          if ([...query.keys()].some(key => key !== "after") || query.getAll("after").length > 1 ||
            after !== null && !UUID.test(after)) return problem(400);
          return context.json(await accounts.listCredentials(session, after));
        }
        if (method !== "POST") return problem(405);
        if (query.size) return problem(400);
        if (session.migration_state) return problem(409);
        if (context.req.header("Content-Type") !== "application/json" || context.req.header("Content-Encoding") !== undefined) return problem(415);
        const bytes=await accountRequestBytes(context.req.raw);if(!bytes||bytes.length>16384)return problem(413);
        let input;
        try { input = parseJsonWithoutDuplicateKeys(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Record<string, unknown>; }
        catch { return problem(400); }
        if (!input || typeof input !== "object" || Array.isArray(input)) return problem(400);
        if (Object.keys(input).length === 1 && typeof input.revoke === "string") {
          if (!UUID.test(input.revoke)) return problem(400);
          await accounts.revoke(input.revoke,session.account_id);return context.json({revoked:true});
        }
        if (Object.keys(input).some(key => !["token", "scopes"].includes(key))) return problem(400);
        if(typeof input.token!=="string" || !/^hailp_[A-Za-z0-9_-]{43}$/.test(input.token))return problem(400);
        const scopes = input.scopes === undefined ? session.scopes : input.scopes;
        if (!Array.isArray(scopes) || !scopes.length || new Set(scopes).size !== scopes.length ||
          scopes.some(scope => !ALL_ACCOUNT_SCOPES.includes(scope))) return problem(400);
        if (scopes.some(scope => !session.scopes.includes(scope))) return problem(403);
        const credential=await accounts.issue(session.canonical_address,false,input.token,scopes);
        return context.json({type:"hailp.api-credential",version:1,provider,...credential});
      }
      if (action === "managed-revoke") {
        if (method !== "POST") return problem(405);
        if(session.migration_state)return problem(409);
        if(!await accounts.isManaged(session.account_id))return problem(403);
        const current=await grants.findCurrentByGrantId(grantId!);
        if(!current||current.localAccountId!==session.account_id||current.localRole!=="grantor")return problem(404);
        const saved=await service.revoke(session.canonical_address,grantId!);
        return context.json({grantId,revision:saved.payload.revision,status:saved.payload.status,digest:encodeBase64Url(saved.digest),publication:"durable"});
      }
      if (action === "proposal" || action === "managed-create") {
        if (method !== "POST") return problem(405);
        if (session.migration_state) return problem(409);
        if (context.req.header("Content-Type") !== "application/json" || context.req.header("Content-Encoding") !== undefined) return problem(415);
        const bytes = await accountRequestBytes(context.req.raw);
        if (!bytes || bytes.length > 16_384) return problem(413);
        const input = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        if (!input || typeof input !== "object" || Array.isArray(input) ||
          Object.keys(input).some(key => !["sender", "category", "expiresAt"].includes(key)) ||
          typeof input.sender !== "string" || (input.category !== null && typeof input.category !== "string") ||
          (input.expiresAt !== null && !Number.isSafeInteger(input.expiresAt))) return problem(400);
        if(action === "managed-create") {
          if(!await accounts.isManaged(session.account_id))return problem(403);
          const saved=await service.createOrReuse(session.canonical_address,input.sender,
            {scope:input.category===null?{type:"uncategorized"}:{type:"categories",values:[input.category]},expiresAt:input.expiresAt});
          return context.json({grantId:saved.payload.grant_id,revision:saved.payload.revision,status:saved.payload.status,digest:encodeBase64Url(saved.digest),publication:"durable"});
        }
        const payload = await service.prepareUserSignedGrant(session.canonical_address, input.sender,
          { scope: input.category === null ? { type: "uncategorized" } : { type: "categories", values: [input.category] }, expiresAt: input.expiresAt });
        return context.json({ type: "hailp.grant-proposal", version: 1, grant: toDiagnosticJson("hail.grant", payload) });
      }
      if (action === "list") {
        if (method !== "GET") return problem(405);
        if ([...query.keys()].some(key => key !== "after")) return problem(400);
        const after = query.get("after");
        if (after !== null && !GRANT_ID.test(after)) return problem(400);
        return context.json(await accounts.listGrants(session, after));
      }
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
      const representation = await accountRequestBytes(context.req.raw);
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
      if (error instanceof HailCodecError || error instanceof SyntaxError) return problem(400);
      if (error instanceof CredentialConflictError || error instanceof GrantConflictError || error instanceof Error &&
        ("code" in error && error.code === "55000" || "errno" in error && error.errno === "55000")) {
        return problem(409);
      }
      context.header("Retry-After", "30");
      return problem(503);
    }
  };
  app.all("/api/v1/account", context => handle(context, null));
  app.all("/api/v1/account/messages",context=>handle(context,null,"send"));
  app.all("/api/v1/account/inbox",context=>handle(context,null,"inbox"));
  app.all("/api/v1/account/inbox/:sender/:messageId",context=>handle(context,context.req.param("messageId"),"read"));
  app.all("/api/v1/account/messages/:messageId/submit",context=>handle(context,context.req.param("messageId"),"resubmit"));
  app.all("/api/v1/account/messages/:messageId",context=>handle(context,context.req.param("messageId"),"status"));
  app.all("/api/v1/account/credentials", context => handle(context,null,"credential"));
  app.all("/api/v1/account/grants/managed", context => handle(context,null,"managed-create"));
  app.all("/api/v1/account/grants/:grantId/revoke", context => handle(context,context.req.param("grantId"),"managed-revoke"));
  app.all("/api/v1/account/grants/proposals", context => handle(context, null, "proposal"));
  app.all("/api/v1/account/grants", context => handle(context, null, "list"));
  app.all("/api/v1/account/grants/:grantId", context => handle(context, context.req.param("grantId")));
}
