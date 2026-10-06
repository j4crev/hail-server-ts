import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createWebCryptoSigner, encodeBase64Url, signPayload,
  type HailAddressBinding, type HailSenderProfile } from "@hailproto/codec";
import { base58btc } from "multiformats/bases/base58";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ProviderDatabase } from "../src/db/database.js";
import { GrantRepository } from "../src/grants/repository.js";
import { GrantService } from "../src/grants/service.js";
import type { VerifiedAddress } from "../src/discovery/verifier.js";
import type { KeyEncryptor } from "../src/identity/key-encryption.js";
import { OnboardingRepository } from "../src/onboarding/repository.js";
import type { HailDidResolver } from "../src/plc/resolver.js";
import type { VerifiedSenderProfile } from "../src/profiles/store.js";

const integration = process.env.DATABASE_URL ? describe : describe.skip;
function didKey(key: CryptoKey): Promise<string> {
  return crypto.subtle.exportKey("raw", key).then((raw) => {
    const prefixed = new Uint8Array(34);
    prefixed.set([0xed, 0x01]);
    prefixed.set(new Uint8Array(raw), 2);
    return `did:key:${base58btc.encode(prefixed)}`;
  });
}

integration("user-held authoritative Grant", () => {
  let database: ProviderDatabase;
  async function clearDisposableGrants(): Promise<void> {
    await database.sql.begin(async (tx) => {
      const ids = await tx<{ grant_id: string; local_account_id: string }[]>`
        SELECT lineage.grant_id, lineage.local_account_id FROM grant_lineages lineage
        JOIN provider_accounts account ON account.id = lineage.local_account_id
        WHERE account.canonical_address LIKE 'grantor-%@source.example.com'`;
      for (const row of ids) {
        await tx`DELETE FROM grant_publications WHERE grant_id = ${row.grant_id}`;
        await tx`DELETE FROM grant_consent_evidence WHERE grant_id = ${row.grant_id}`;
        await tx`DELETE FROM grant_revisions WHERE grant_id = ${row.grant_id}`;
        await tx`DELETE FROM grant_lineages WHERE grant_id = ${row.grant_id}`;
        await tx`DELETE FROM provider_accounts WHERE id = ${row.local_account_id}`;
      }
    });
  }
  beforeAll(async () => {
    database = new ProviderDatabase(process.env.DATABASE_URL!);
    await database.migrate();
    await clearDisposableGrants();
  });
  afterAll(async () => { if (database) {
    await clearDisposableGrants();
    await database.close();
  } });

  it("persists exact user-signed consent evidence and publisher work without a provider identity key", async () => {
    const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    const freshDid = () => `did:plc:${Array.from(randomBytes(24), (value) => alphabet[value % 32]).join("")}`;
    const grantorDid = freshDid();
    const senderDid = freshDid();
    const grantorAddress = `grantor-${randomUUID()}@source.example.com`;
    const senderAddress = `sender-${randomUUID()}@target.example.com`;
    const accountId = randomUUID();
    await database.sql`INSERT INTO provider_accounts (id, tenant_id, canonical_address,
      did, onboarding_state, activated_at, activation_binding_digest, activation_verification_mode)
      VALUES (${accountId}, ${randomUUID()}, ${grantorAddress}, ${grantorDid},
        'active', now(), ${randomBytes(32)}, 'public')`;
    const user = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const sender = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const senderIdentity = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const userDidKey = await didKey(user.publicKey);
    const senderDidKey = await didKey(sender.publicKey);
    const senderIdentityDidKey = await didKey(senderIdentity.publicKey);
    const evidence = { document: {}, data: {}, log: [] };
    const resolver: HailDidResolver = { async resolve(value) {
      if (value !== grantorDid) throw new Error("Unexpected DID");
      return { did: grantorDid, identityDidKey: userDidKey, messagingDidKey: senderDidKey,
        serviceBase: "https://source.example.com/hail", evidence };
    } };
    const now = Math.floor(Date.now() / 1000);
    const addressBinding: HailAddressBinding = { type: "hail.address-binding", version: 1,
      address: senderAddress, did: senderDid, issued_at: now, expires_at: now + 3600,
      key_id: `${senderDid}#hail-identity` };
    const signedBinding = await signPayload("hail.address-binding", addressBinding,
      createWebCryptoSigner(addressBinding.key_id, senderIdentity.privateKey));
    const bindingDigest = new Uint8Array(createHash("sha256").update(signedBinding).digest());
    const address: VerifiedAddress = { address: senderAddress, did: senderDid,
      serviceBase: "https://target.example.com/hail", messagingDidKey: senderDidKey,
      identityDidKey: senderIdentityDidKey, plcEvidence: evidence, verifiedAt: new Date(),
      binding: addressBinding, representation: signedBinding, digest: bindingDigest };
    const profile: HailSenderProfile = { type: "hail.sender-profile", version: 1,
      did: senderDid, revision: 1, display_name: "Test sender", offers_uncategorized: false,
      categories: [{ id: "updates", label: "Updates" }], updated_at: now,
      key_id: `${senderDid}#hail-messaging` };
    const signedProfile = await signPayload("hail.sender-profile", profile,
      createWebCryptoSigner(profile.key_id, sender.privateKey));
    const verifiedProfile: VerifiedSenderProfile = {
      did: senderDid, serviceBase: address.serviceBase, messagingDidKey: senderDidKey,
      profile, representation: signedProfile,
      digest: new Uint8Array(createHash("sha256").update(signedProfile).digest()),
      plcEvidence: evidence, verifiedAt: new Date(), etag: encodeBase64Url(
        new Uint8Array(createHash("sha256").update(signedProfile).digest())),
    };
    const grants = new GrantRepository(database.sql);
    const service = new GrantService(new OnboardingRepository(database.sql), grants,
      { async decrypt() { throw new Error("Provider must not decrypt the user's identity"); } } as unknown as KeyEncryptor,
      resolver, { async verify() { return address; } }, { async verify() { return verifiedProfile; } },
      "https://source.example.com/hail");
    const proposed = await service.prepareUserSignedGrant(grantorAddress, senderAddress,
      { scope: { type: "categories", values: ["updates"] }, expiresAt: now + 86400 });
    const representation = await signPayload("hail.grant", proposed,
      createWebCryptoSigner(proposed.key_id, user.privateKey));
    const stored = await service.acceptUserSignedGrant(grantorAddress, senderAddress, representation);
    expect(stored.payload).toEqual(proposed);
    expect((await service.acceptUserSignedGrant(grantorAddress, senderAddress, representation)).digest)
      .toEqual(stored.digest);
    expect(await database.sql`SELECT role FROM account_keys WHERE account_id = ${accountId}`)
      .toHaveLength(0);
    expect(await database.sql`SELECT grant_id FROM grant_publications WHERE grant_id = ${proposed.grant_id}`)
      .toHaveLength(1);
    const corrupted = Uint8Array.from(representation);
    corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
    await expect(service.acceptUserSignedGrant(grantorAddress, senderAddress, corrupted)).rejects.toThrow();
  });
});
