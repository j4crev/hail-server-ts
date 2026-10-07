import { createHash, randomBytes, randomUUID } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createWebCryptoSigner, encodeBase64Url, signPayload, type HailAddressBinding,
  type HailSenderProfile } from "@hailproto/codec";
import { base58btc } from "multiformats/bases/base58";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createUserVault, unlockUserVault } from "../../hail-user-client-ts/src/vault.js";
import { signGrantRevocation } from "../../hail-user-client-ts/src/grant-revocation.js";
import { AccountApiRepository } from "../src/accounts/repository.js";
import { createApp } from "../src/app.js";
import type { AppConfig } from "../src/config.js";
import { ProviderDatabase } from "../src/db/database.js";
import type { VerifiedAddress } from "../src/discovery/verifier.js";
import { GrantRepository } from "../src/grants/repository.js";
import { GrantService } from "../src/grants/service.js";
import type { KeyEncryptor } from "../src/identity/key-encryption.js";
import { OnboardingRepository } from "../src/onboarding/repository.js";
import type { HailDidResolver } from "../src/plc/resolver.js";
import type { VerifiedSenderProfile } from "../src/profiles/store.js";

const integration = process.env.DATABASE_URL ? describe : describe.skip;
const freshDid = () => `did:plc:${Array.from(randomBytes(24), b => "abcdefghijklmnopqrstuvwxyz234567"[b % 32]).join("")}`;
async function didKey(key: CryptoKey) {
  const bytes = new Uint8Array(34);
  bytes.set([0xed, 0x01]);
  bytes.set(new Uint8Array(await crypto.subtle.exportKey("raw", key)), 2);
  return `did:key:${base58btc.encode(bytes)}`;
}

integration("authenticated account API and real hailp HTTPS CLI", () => {
  let db: ProviderDatabase;
  let accounts: AccountApiRepository;
  let grants: GrantRepository;
  let server: ReturnType<typeof Bun.serve>;
  let receiver: ReturnType<typeof Bun.serve>;
  let app: ReturnType<typeof createApp>;
  let directory: string;
  let origin: string;
  let credential: Awaited<ReturnType<AccountApiRepository["issue"]>>;
  let readonlyCredential: Awaited<ReturnType<AccountApiRepository["issue"]>>;
  let vault: Awaited<ReturnType<typeof createUserVault>>;
  let signedGrant: Uint8Array;
  let grantId: string;
  let senderAvailable = true;
  let redirect = false;
  let losePutResponse = false;
  let redirectedRequests = 0;
  const ownerId = randomUUID();
  const otherId = randomUUID();
  const senderId = randomUUID();
  const did = freshDid();
  const otherDid = freshDid();
  const senderDid = freshDid();
  const address = `api-owner-${randomUUID()}@source.example.com`;
  const senderAddress = `api-sender-${randomUUID()}@target.example.com`;
  const otherAddress = `api-other-${randomUUID()}@source.example.com`;
  const authorization = () => ({ Authorization: `Bearer ${credential.token}` });
  const grantUrl = () => `${origin}/api/v1/account/grants/${grantId}`;
  const json = async (path: string, value: unknown) => writeFile(join(directory, path), JSON.stringify(value), { mode: 0o600 });
  const credentialRecord = (value: Awaited<ReturnType<AccountApiRepository["issue"]>>) =>
    ({ type: "hailp.api-credential", version: 1, provider: origin, ...value });

  async function cli(args: string[], filename = "owner.credential.json", secret = false) {
    const child = Bun.spawn(["bun", "src/cli/hailp.ts", ...args, "--credentials", join(directory, filename)], {
      cwd: new URL("../../hail-user-client-ts/", import.meta.url).pathname,
      env: { ...Bun.env, NODE_EXTRA_CA_CERTS: join(directory, "cert.pem") },
      stdin: "pipe", stdout: "pipe", stderr: "pipe",
    });
    if (secret) child.stdin.write(`${encodeBase64Url(vault.recoverySecret)}\n`);
    child.stdin.end();
    const [exit, stdout, stderr] = await Promise.all([child.exited,
      new Response(child.stdout).text(), new Response(child.stderr).text()]);
    expect(stdout + stderr).not.toContain(credential.token);
    if (secret) expect(stdout + stderr).not.toContain(encodeBase64Url(vault.recoverySecret));
    return { exit, stdout, stderr };
  }

  beforeAll(async () => {
    db = new ProviderDatabase(process.env.DATABASE_URL!);
    await db.migrate();
    accounts = new AccountApiRepository(db.sql);
    grants = new GrantRepository(db.sql);
    directory = await mkdtemp(join(tmpdir(), "hailp-api-"));
    const openssl = Bun.spawn(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
      "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
      "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", join(directory, "key.pem"),
      "-out", join(directory, "cert.pem")], { stdout: "pipe", stderr: "pipe" });
    if (await openssl.exited !== 0) throw new Error(await new Response(openssl.stderr).text());
    const tls = { cert: Bun.file(join(directory, "cert.pem")), key: Bun.file(join(directory, "key.pem")) };
    receiver = Bun.serve({ hostname: "localhost", port: 0, tls,
      fetch() { redirectedRequests++; return Response.json({}); } });
    server = Bun.serve({ hostname: "localhost", port: 0, tls, async fetch(request) {
      if (redirect) return new Response(null, { status: 302, headers: { Location: `https://localhost:${receiver.port}/` } });
      const response = await app.fetch(request);
      if (losePutResponse && request.method === "PUT" && response.ok) {
        losePutResponse = false;
        return new Response(null, { status: 503 });
      }
      return response;
    } });
    origin = `https://localhost:${server.port}`;
    for (const [id, accountDid, accountAddress] of [[ownerId, did, address], [otherId, otherDid, otherAddress],
      [senderId, senderDid, senderAddress]] as const) {
      await db.sql`INSERT INTO provider_accounts (id,tenant_id,canonical_address,did,onboarding_state,
        activated_at,activation_binding_digest,activation_verification_mode)
        VALUES (${id},${randomUUID()},${accountAddress},${accountDid},'active',now(),${randomBytes(32)},'public')`;
    }
    vault = await createUserVault();
    vault.vault.did = did;
    const user = await unlockUserVault(JSON.parse(JSON.stringify(vault.vault)), vault.recoverySecret);
    await db.sql`INSERT INTO portable_custody_evidence (account_id,user_recovery_public_key,user_identity_public_key,
      monitor_origin,monitor_confirmed_at,backup_confirmed_at,monitor_verification_mode)
      VALUES (${ownerId},${vault.vault.recovery.publicDidKey},${vault.vault.identity.publicDidKey},
        'https://monitor.example.com',now(),now(),'poc-local')`;
    const sender = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const senderIdentity = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const senderKey = await didKey(sender.publicKey);
    const senderIdentityKey = await didKey(senderIdentity.publicKey);
    const evidence = { document: {}, data: {}, log: [] };
    const resolver: HailDidResolver = { async resolve(value) {
      if (value !== did) throw new Error("No sender lookup is allowed for revocation");
      return { did, identityDidKey: vault.vault.identity.publicDidKey, messagingDidKey: senderKey,
        serviceBase: `${origin}/hail`, evidence };
    } };
    const now = Math.floor(Date.now() / 1000);
    const binding: HailAddressBinding = { type: "hail.address-binding", version: 1, address: senderAddress,
      did: senderDid, issued_at: now, expires_at: now + 3600, key_id: `${senderDid}#hail-identity` };
    const bindingBytes = await signPayload("hail.address-binding", binding, createWebCryptoSigner(binding.key_id, senderIdentity.privateKey));
    const verifiedAddress: VerifiedAddress = { address: senderAddress, did: senderDid, binding,
      representation: bindingBytes, digest: new Uint8Array(createHash("sha256").update(bindingBytes).digest()),
      serviceBase: "https://target.example.com/hail", identityDidKey: senderIdentityKey, messagingDidKey: senderKey,
      plcEvidence: evidence, verifiedAt: new Date() };
    const profile: HailSenderProfile = { type: "hail.sender-profile", version: 1, did: senderDid, revision: 1,
      display_name: "API sender", offers_uncategorized: false, categories: [{ id: "updates", label: "Updates" }],
      updated_at: now, key_id: `${senderDid}#hail-messaging` };
    const profileBytes = await signPayload("hail.sender-profile", profile, createWebCryptoSigner(profile.key_id, sender.privateKey));
    const verifiedProfile: VerifiedSenderProfile = { did: senderDid, profile, representation: profileBytes,
      digest: new Uint8Array(createHash("sha256").update(profileBytes).digest()), serviceBase: verifiedAddress.serviceBase,
      messagingDidKey: senderKey, plcEvidence: evidence, verifiedAt: new Date(), etag: "test-profile" };
    const service = new GrantService(new OnboardingRepository(db.sql), grants,
      { async decrypt() { throw new Error("Provider must never decrypt user keys"); } } as unknown as KeyEncryptor,
      resolver, { async verify() { if (!senderAvailable) throw new Error("Sender offline"); return verifiedAddress; } },
      { async verify() { if (!senderAvailable) throw new Error("Sender offline"); return verifiedProfile; } }, `${origin}/hail`);
    const proposed = await service.prepareUserSignedGrant(address, senderAddress,
      { scope: { type: "categories", values: ["updates"] }, expiresAt: now + 86400 });
    grantId = proposed.grant_id;
    signedGrant = await user.signGrant(proposed);
    app = createApp({ publicOrigin: origin, hailServiceBase: `${origin}/hail`, providerId: "test" } as AppConfig,
      { accountApi: { accounts, grants, service }, async checkReadiness() { return { ready: true }; } });
    await json("vault.json", vault.vault);
    await writeFile(join(directory, "initial.cose"), signedGrant, { mode: 0o600 });
    const bootstrap = Bun.spawn(["bun", "src/cli/create-account-credential.ts", address,
      join(directory, "owner.credential.json"), "--write-grants"], { env: { ...Bun.env,
      DATABASE_URL: process.env.DATABASE_URL!, NODE_ENV: "test", PORT: "3000", PROVIDER_ID: "test",
      PUBLIC_ORIGIN: origin, HAIL_SERVICE_BASE: `${origin}/hail`, PLC_DIRECTORY_URL: "http://plc.fixture:2582",
      KEY_ENCRYPTION_KEY: encodeBase64Url(randomBytes(32)) }, stdout: "pipe", stderr: "pipe" });
    if (await bootstrap.exited !== 0) throw new Error(await new Response(bootstrap.stderr).text());
    credential = JSON.parse(await readFile(join(directory, "owner.credential.json"), "utf8"));
    expect(await new Response(bootstrap.stdout).text()).not.toContain(credential.token);
    readonlyCredential = await accounts.issue(address);
    await json("readonly.credential.json", credentialRecord(readonlyCredential));
  });

  afterAll(async () => {
    server?.stop(true);
    receiver?.stop(true);
    if (db) {
      await db.sql`DELETE FROM provider_migration_fences WHERE account_id IN (${ownerId},${otherId},${senderId})`;
      await db.sql`DELETE FROM account_api_credentials WHERE account_id IN (${ownerId},${otherId},${senderId})`;
      if (grantId) {
        await db.sql`DELETE FROM collocated_grant_receivers WHERE grant_id = ${grantId}`;
        await db.sql`DELETE FROM grant_publications WHERE grant_id = ${grantId}`;
        await db.sql`DELETE FROM grant_consent_evidence WHERE grant_id = ${grantId}`;
        await db.sql`DELETE FROM grant_revisions WHERE grant_id = ${grantId}`;
        await db.sql`DELETE FROM grant_lineages WHERE grant_id = ${grantId}`;
      }
      await db.sql`DELETE FROM portable_custody_evidence WHERE account_id = ${ownerId}`;
      await db.sql`DELETE FROM provider_accounts WHERE id IN (${ownerId},${otherId},${senderId})`;
      await db.close();
    }
    vault?.recoverySecret.fill(0);
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  it("bootstraps a hashed credential and runs real HTTPS account/show/signed-import commands", async () => {
    const missing = await app.request(`${origin}/api/v1/account`);
    expect(missing.status).toBe(401);
    expect(missing.headers.get("Cache-Control")).toBe("no-store");
    expect(missing.headers.get("Content-Type")).toBe("application/problem+json");
    const result = await cli(["account", "show"]);
    if (result.exit) throw new Error(result.stderr);
    expect(JSON.parse(result.stdout)).toMatchObject({ accountId: ownerId, did, custodyProfile: "owner-controlled",
      monitorVerificationMode: "poc-local", identityPublicKey: vault.vault.identity.publicDidKey });
    const imported = await cli(["grant", "submit", join(directory, "initial.cose")]);
    if (imported.exit) throw new Error(imported.stderr);
    expect(JSON.parse(imported.stdout)).toMatchObject({ grantId, revision: 1, status: "active" });
    expect((await cli(["grant", "submit", join(directory, "initial.cose")])).exit).toBe(0);
    const shown = await cli(["grant", "show", grantId, "--output", join(directory, "copy.cose")]);
    if (shown.exit) throw new Error(shown.stderr);
    expect(JSON.parse(shown.stdout)).toMatchObject({ grantId, localRole: "grantor" });
    expect(new Uint8Array(await readFile(join(directory, "copy.cose")))).toEqual(signedGrant);
    const rows = await db.sql<{ token_hash: Uint8Array }[]>`SELECT token_hash FROM account_api_credentials WHERE id=${credential.credentialId}`;
    expect(Buffer.from(rows[0]!.token_hash).toString("hex")).toBe(createHash("sha256").update(credential.token).digest("hex"));
    expect(await db.sql`SELECT role FROM account_keys WHERE account_id=${ownerId}`).toHaveLength(0);
  });

  it("enforces scopes, cross-account isolation and collocated sender read-only ownership", async () => {
    const put = (headers: HeadersInit) => app.request(grantUrl(), { method: "PUT", headers,
      body: Uint8Array.from(signedGrant) });
    expect((await put({ Authorization: `Bearer ${readonlyCredential.token}` })).status).toBe(403);
    const readonlyOutput = join(directory, "readonly-revocation.cose");
    const readonlyAttempt = await cli(["grant", "revoke", grantId, "--vault", join(directory, "vault.json"),
      "--output", readonlyOutput], "readonly.credential.json", true);
    expect(readonlyAttempt.exit).toBe(1);
    expect(readonlyAttempt.stderr).toContain("write permission");
    await expect(readFile(readonlyOutput)).rejects.toMatchObject({ code: "ENOENT" });
    const other = await accounts.issue(otherAddress, true);
    expect((await app.request(grantUrl(), { headers: { Authorization: `Bearer ${other.token}` } })).status).toBe(404);
    expect((await put({ Authorization: `Bearer ${other.token}`, "Content-Type": 'application/cose; cose-type="cose-sign1"' })).status).toBe(404);
    await db.sql`INSERT INTO collocated_grant_receivers (grant_id,grantee_account_id) VALUES (${grantId},${senderId})`;
    const sender = await accounts.issue(senderAddress, true);
    await json("sender.credential.json", credentialRecord(sender));
    const shown = await cli(["grant", "show", grantId], "sender.credential.json");
    expect(shown.exit).toBe(0);
    expect(JSON.parse(shown.stdout).localRole).toBe("grantee");
    const refused = await cli(["grant", "revoke", grantId, "--vault", join(directory, "vault.json"),
      "--output", join(directory, "wrong.cose")], "sender.credential.json", true);
    expect(refused.exit).toBe(1);
    expect(refused.stderr).toContain("authoritative grantor");
    const bad = Uint8Array.from(signedGrant);
    bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
    expect((await app.request(grantUrl(), { method: "PUT", headers: { ...authorization(),
      "Content-Type": 'application/cose; cose-type="cose-sign1"' }, body: bad })).status).toBe(400);
    expect((await grants.findCurrentByGrantId(grantId))?.payload.status).toBe("active");
  });

  it("rejects fenced writes and recovers a committed revocation after a lost response without user keys at the provider", async () => {
    senderAvailable = false;
    const revoked = await signGrantRevocation(join(directory, "vault.json"), signedGrant, grantId,
      senderAddress, join(directory, "fence.cose"), vault.recoverySecret);
    await db.sql`INSERT INTO provider_migration_fences (did,account_id,transfer_id,destination_service_base,state)
      VALUES (${did},${ownerId},${randomUUID()},'https://target.example.com/hail','fenced')`;
    expect((await app.request(grantUrl(), { method: "PUT", headers: { ...authorization(),
      "Content-Type": 'application/cose; cose-type="cose-sign1"' }, body: Uint8Array.from(revoked) })).status).toBe(409);
    await expect(accounts.issue(address)).rejects.toThrow("migration-fenced");
    expect((await grants.findCurrentByGrantId(grantId))?.payload.status).toBe("active");
    await db.sql`DELETE FROM provider_migration_fences WHERE account_id=${ownerId}`;
    const args = ["grant", "revoke", grantId, "--vault", join(directory, "vault.json"),
      "--output", join(directory, "revoked.cose")];
    losePutResponse = true;
    const lost = await cli(args, "owner.credential.json", true);
    expect(lost.exit).toBe(1);
    expect(lost.stderr).toContain("HTTP_503");
    const first = await readFile(join(directory, "revoked.cose"));
    const retry = await cli(args, "owner.credential.json", true);
    if (retry.exit) throw new Error(retry.stderr);
    expect(JSON.parse(retry.stdout)).toMatchObject({ grantId, status: "revoked", revision: 2 });
    expect(await readFile(join(directory, "revoked.cose"))).toEqual(first);
    expect(await db.sql`SELECT revision FROM grant_revisions WHERE grant_id=${grantId}`).toHaveLength(2);
    expect(await db.sql`SELECT revision FROM grant_publications WHERE grant_id=${grantId}`).toHaveLength(2);
    expect((await grants.findReceivedForSender(grantId, senderDid))?.payload.status).toBe("revoked");
    expect(await db.sql`SELECT role FROM account_keys WHERE account_id=${ownerId}`).toHaveLength(0);
  });

  it("bounds transport and authenticates before revealing account or Grant validation", async () => {
    expect((await app.request(`${origin}/api/v1/account/grants/not-an-id`)).status).toBe(401);
    expect((await app.request(grantUrl(), { method: "POST", headers: authorization() })).status).toBe(405);
    expect((await app.request(`${origin}/api/v1/account?account=${otherId}`, { headers: authorization() })).status).toBe(400);
    expect((await app.request(grantUrl(), { method: "PUT", headers: { ...authorization(),
      "Content-Type": "application/json" }, body: "{}" })).status).toBe(415);
    expect((await app.request(grantUrl(), { method: "PUT", headers: { ...authorization(),
      "Content-Type": 'application/cose; cose-type="cose-sign1"' }, body: new Uint8Array(262_145) })).status).toBe(413);
    const hidden = await cli(["account", "show"], credential.token);
    expect(hidden.exit).toBe(1);
    expect(hidden.stderr).toContain("[REDACTED]");
  });

  it("rejects redirects, insecure credential files, expired credentials and revoked credentials", async () => {
    redirect = true;
    try {
      const refused = await cli(["account", "show"]);
      expect(refused.exit).toBe(1);
      expect(redirectedRequests).toBe(0);
    } finally { redirect = false; }
    const file = join(directory, "readonly.credential.json");
    await chmod(file, 0o644);
    expect((await cli(["account", "show"], "readonly.credential.json")).exit).toBe(1);
    await chmod(file, 0o600);
    await db.sql`UPDATE account_api_credentials SET created_at=now()-interval '2 days',
      expires_at=now()-interval '1 day' WHERE id=${readonlyCredential.credentialId}`;
    const expired = await cli(["account", "show"], "readonly.credential.json");
    expect(expired.stderr).toContain("HTTP_401");
    await accounts.revoke(credential.credentialId);
    await accounts.revoke(credential.credentialId);
    const revoked = await cli(["account", "show"]);
    expect(revoked.stderr).toContain("HTTP_401");
  });
});
