import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  createWebCryptoSigner,
  createWebCryptoVerifier,
  signPayload,
  verifySignedPayload,
  type HailGrant,
  type HailGrantScope,
} from "@hailproto/codec";
import type { AddressVerifier } from "../discovery/verifier.js";
import { canonicalizeHailAddress } from "../identity/address.js";
import { ed25519PublicKeyFromDidKey } from "../identity/did-key.js";
import type { KeyEncryptor } from "../identity/key-encryption.js";
import { importEd25519PrivateKey } from "../identity/keys.js";
import { uuidV7 } from "../identity/uuid-v7.js";
import type { AccountKeyRecord, AccountRecord } from "../onboarding/repository.js";
import type { HailDidResolver } from "../plc/resolver.js";
import type { PlcResolutionEvidence } from "../plc/resolver.js";
import type { SenderProfileVerifier } from "../profiles/verifier.js";
import type { GrantStore, SignedGrantRevision, SignedGrantRevisionInput } from "./store.js";
import { inspectSignedPayload } from "@hailproto/codec";

export interface GrantAccountRepository {
  getAccountByAddress(address: string): Promise<AccountRecord>;
  getKey(accountId: string, role: AccountKeyRecord["role"]): Promise<AccountKeyRecord>;
}

export interface GrantDefinition {
  scope: HailGrantScope;
  expiresAt: number | null;
}

export class UserGrantError extends Error {
  constructor(readonly status: 400 | 409, message: string) { super(message); }
}

function normalizeScope(scope: HailGrantScope): HailGrantScope {
  if (scope.type === "uncategorized") return { type: "uncategorized" };
  return {
    type: "categories",
    values: [...scope.values].sort((left, right) => Buffer.from(left).compare(Buffer.from(right))),
  };
}

function validateScopeAgainstProfile(
  scope: HailGrantScope,
  profile: Awaited<ReturnType<SenderProfileVerifier["verify"]>>["profile"],
): void {
  if (scope.type === "uncategorized") {
    if (!profile.offers_uncategorized) {
      throw new Error("Grantee Sender Profile does not offer uncategorized messages");
    }
    return;
  }
  const offered = new Set(profile.categories.map((category) => category.id));
  if (scope.values.length === 0 || scope.values.some((category) => !offered.has(category))) {
    throw new Error("Grant scope contains a category not offered by the grantee Sender Profile");
  }
}

function digest(value: Uint8Array) {
  return { algorithm: "sha-256" as const, value: Uint8Array.from(value) };
}

export class GrantService {
  constructor(
    private readonly accounts: GrantAccountRepository,
    private readonly grants: GrantStore,
    private readonly encryptor: KeyEncryptor,
    private readonly resolver: HailDidResolver,
    private readonly addressVerifier: Pick<AddressVerifier, "verify">,
    private readonly profileVerifier: Pick<SenderProfileVerifier, "verify">,
    private readonly expectedServiceBase: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  // User-held identities sign outside the provider. The proposal has no
  // authority until the current #hail-identity key signs its exact Hail bytes.
  async prepareUserSignedGrant(grantorAddressInput: string,
    granteeAddressInput: string, input: GrantDefinition): Promise<HailGrant> {
    const grantor = await this.accounts.getAccountByAddress(canonicalizeHailAddress(grantorAddressInput));
    if (grantor.state !== "active" || grantor.activationVerificationMode !== "public" || !grantor.did) {
      throw new Error("Grantor must be an externally verified active account");
    }
    const current = await this.resolver.resolve(grantor.did);
    if (current.serviceBase !== this.expectedServiceBase) {
      throw new Error("Current PLC does not name this grantor provider");
    }
    const address = await this.addressVerifier.verify(canonicalizeHailAddress(granteeAddressInput));
    const profile = await this.profileVerifier.verify(address.did);
    if (profile.did !== address.did || profile.serviceBase !== address.serviceBase ||
      profile.messagingDidKey !== address.messagingDidKey) {
      throw new Error("Grantee Address Binding and Sender Profile disagree");
    }
    const scope = normalizeScope(input.scope);
    validateScopeAgainstProfile(scope, profile.profile);
    const now = Math.floor(this.now().getTime() / 1000);
    if (input.expiresAt !== null && input.expiresAt <= now) throw new Error("Grant expiry is already past");
    if (await this.grants.findActiveAuthoritativeByDidPair(grantor.did, address.did)) {
      throw new Error("This DID pair already has an active authoritative Grant");
    }
    return { type: "hail.grant", version: 1, grant_id: uuidV7(this.now().getTime()),
      revision: 1, previous: null, grantor: grantor.did, grantee: address.did,
      scope: [scope], status: "active", issued_at: now, updated_at: now,
      expires_at: input.expiresAt,
      consent_context: { grantee_address: address.address,
        address_binding_hash: digest(address.digest), sender_profile_hash: digest(profile.digest) },
      key_id: `${grantor.did}#hail-identity` };
  }

  async acceptUserSignedGrant(grantorAddressInput: string,
    granteeAddressInput: string, representation: Uint8Array): Promise<SignedGrantRevision> {
    if (representation.length < 1 || representation.length > 262_144) throw new UserGrantError(400, "Grant exceeds its limit");
    const grantor = await this.accounts.getAccountByAddress(canonicalizeHailAddress(grantorAddressInput));
    if (grantor.state !== "active" || grantor.activationVerificationMode !== "public" || !grantor.did) {
      throw new UserGrantError(409, "Grantor account is not active and externally verified");
    }
    const resolved = await this.resolver.resolve(grantor.did);
    if (resolved.serviceBase !== this.expectedServiceBase) throw new UserGrantError(409, "Grantor provider is no longer current");
    const payload = inspectSignedPayload("hail.grant", representation).payload;
    if (payload.grantor !== grantor.did || payload.key_id !== `${grantor.did}#hail-identity`) {
      throw new UserGrantError(400, "User-signed Grant has invalid authority");
    }
    try {
      await verifySignedPayload("hail.grant", representation,
        createWebCryptoVerifier(async (kid) => {
          if (kid !== `${grantor.did}#hail-identity`) throw new Error("Unexpected Grant identity signer");
          return ed25519PublicKeyFromDidKey(resolved.identityDidKey);
        }));
    } catch { throw new UserGrantError(400, "User-signed Grant signature is invalid"); }
    const now = Math.floor(this.now().getTime() / 1000);
    const signed: SignedGrantRevisionInput = { localAccountId: grantor.id, localRole: "grantor",
      payload, representation, digest: new Uint8Array(createHash("sha256").update(representation).digest()),
      signingPublicKey: resolved.identityDidKey, signingPlcEvidence: resolved.evidence };
    if (payload.issued_at > now + 300 || payload.updated_at > now + 300) {
      throw new UserGrantError(400, "User-signed Grant timestamp is too far ahead");
    }
    if (payload.status === "revoked") {
      const current = await this.grants.findCurrentByGrantId(payload.grant_id);
      if (!current || current.localRole !== "grantor" || current.localAccountId !== grantor.id ||
        current.payload.grantor !== grantor.did ||
        payload.consent_context.grantee_address !== canonicalizeHailAddress(granteeAddressInput)) {
        throw new UserGrantError(409, "Authoritative Grant or reviewed sender does not match revocation");
      }
      if (Buffer.from(current.representation).equals(Buffer.from(representation))) return current;
      if (current.payload.status !== "active" || payload.updated_at <= current.payload.updated_at ||
        !isDeepStrictEqual(payload, { ...current.payload, status: "revoked",
          revision: current.payload.revision + 1, previous: Uint8Array.from(current.digest),
          updated_at: payload.updated_at, key_id: `${grantor.did}#hail-identity` })) {
        throw new UserGrantError(409, "User-signed Grant revocation conflicts with the current revision");
      }
      // Restriction needs retained consent only, never the sender's availability.
      try {
        await this.grants.appendAuthoritativeRevocation({ revision: signed,
          expectedCurrentRevision: current.payload.revision, expectedCurrentDigest: current.digest });
      } catch (error) {
        const winner = await this.grants.findCurrentByGrantId(payload.grant_id);
        if (winner?.localRole === "grantor" && winner.localAccountId === grantor.id &&
          Buffer.from(winner.representation).equals(Buffer.from(representation))) return winner;
        throw error;
      }
      return { ...signed, receivedAt: this.now() };
    }
    if (payload.revision !== 1 || payload.previous !== null || payload.updated_at !== payload.issued_at) {
      throw new UserGrantError(409, "User-signed initial Grant has invalid authority");
    }
    if (payload.expires_at !== null && payload.expires_at <= now) {
      throw new UserGrantError(400, "User-signed Grant is stale or expired");
    }
    const address = await this.addressVerifier.verify(canonicalizeHailAddress(granteeAddressInput));
    const profile = await this.profileVerifier.verify(address.did);
    if (payload.grantee !== address.did ||
      payload.consent_context.grantee_address !== address.address ||
      profile.did !== address.did || profile.serviceBase !== address.serviceBase ||
      profile.messagingDidKey !== address.messagingDidKey ||
      !Buffer.from(payload.consent_context.address_binding_hash.value).equals(Buffer.from(address.digest)) ||
      !Buffer.from(payload.consent_context.sender_profile_hash.value).equals(Buffer.from(profile.digest))) {
      throw new UserGrantError(400, "Grant consent no longer matches current verified grantee evidence");
    }
    if (payload.scope.length !== 1 ||
      !isDeepStrictEqual(payload.scope[0], normalizeScope(payload.scope[0]!))) {
      throw new UserGrantError(400, "User Grant scope is not canonical");
    }
    try { validateScopeAgainstProfile(payload.scope[0]!, profile.profile); }
    catch (error) { throw new UserGrantError(400, error instanceof Error ? error.message : "Invalid Grant scope"); }
    const existing = await this.grants.findActiveAuthoritativeByDidPair(grantor.did, address.did);
    if (existing) {
      if (Buffer.from(existing.representation).equals(Buffer.from(representation))) return existing;
      throw new UserGrantError(409, "An active different Grant already exists for these DIDs");
    }
    await this.grants.insertAuthoritativeRevision1({ revision: signed,
      consent: { address, senderProfile: profile }, destinationServiceBase: address.serviceBase });
    return { ...signed, receivedAt: this.now() };
  }

  async createOrReuse(
    grantorAddressInput: string,
    granteeAddressInput: string,
    inputDefinition: GrantDefinition,
  ): Promise<SignedGrantRevision> {
    const grantorAddress = canonicalizeHailAddress(grantorAddressInput);
    const grantor = await this.accounts.getAccountByAddress(grantorAddress);
    if (
      grantor.state !== "active" ||
      grantor.activationVerificationMode !== "public" ||
      !grantor.did
    ) {
      throw new Error("Grantor account must have public activation evidence");
    }
    const identityKey = await this.accounts.getKey(grantor.id, "hail-identity");
    const currentGrantor = await this.resolver.resolve(grantor.did);
    if (
      currentGrantor.identityDidKey !== identityKey.publicKey ||
      currentGrantor.serviceBase !== this.expectedServiceBase
    ) {
      throw new Error("Current PLC state does not authorize this provider identity key");
    }

    const granteeAddress = canonicalizeHailAddress(granteeAddressInput);
    const address = await this.addressVerifier.verify(granteeAddress);
    const senderProfile = await this.profileVerifier.verify(address.did);
    if (
      senderProfile.did !== address.did ||
      senderProfile.serviceBase !== address.serviceBase ||
      senderProfile.messagingDidKey !== address.messagingDidKey
    ) {
      throw new Error("Grantee discovery and Sender Profile evidence do not agree");
    }
    const scope = normalizeScope(inputDefinition.scope);
    validateScopeAgainstProfile(scope, senderProfile.profile);

    const current = Math.floor(this.now().getTime() / 1_000);
    if (inputDefinition.expiresAt !== null && inputDefinition.expiresAt < current) {
      throw new Error("Grant expiry must not precede issuance");
    }
    const existing = await this.grants.findActiveAuthoritativeByDidPair(grantor.did, address.did);
    if (existing) {
      const sameDefinition =
        existing.signingPublicKey === identityKey.publicKey &&
        existing.payload.expires_at === inputDefinition.expiresAt &&
        isDeepStrictEqual(existing.payload.scope, [scope]) &&
        isDeepStrictEqual(existing.payload.consent_context.address_binding_hash.value, address.digest) &&
        isDeepStrictEqual(
          existing.payload.consent_context.sender_profile_hash.value,
          senderProfile.digest,
        );
      if (sameDefinition) return existing;
      throw new Error("An active Grant already exists for this grantor and grantee");
    }

    const payload: HailGrant = {
      type: "hail.grant",
      version: 1,
      grant_id: uuidV7(this.now().getTime()),
      revision: 1,
      previous: null,
      grantor: grantor.did,
      grantee: address.did,
      scope: [scope],
      status: "active",
      issued_at: current,
      updated_at: current,
      expires_at: inputDefinition.expiresAt,
      consent_context: {
        grantee_address: address.address,
        address_binding_hash: digest(address.digest),
        sender_profile_hash: digest(senderProfile.digest),
      },
      key_id: `${grantor.did}#hail-identity`,
    };
    const revision = await this.sign(grantor, identityKey, payload, currentGrantor.evidence);
    await this.grants.insertAuthoritativeRevision1({
      revision,
      consent: { address, senderProfile },
      destinationServiceBase: address.serviceBase,
    });
    return { ...revision, receivedAt: this.now() };
  }

  async revoke(grantorAddressInput: string, grantId: string): Promise<SignedGrantRevision> {
    const grantor = await this.accounts.getAccountByAddress(
      canonicalizeHailAddress(grantorAddressInput),
    );
    if (
      grantor.state !== "active" ||
      grantor.activationVerificationMode !== "public" ||
      !grantor.did
    ) {
      throw new Error("Grantor account must have public activation evidence");
    }
    const current = await this.grants.findCurrentByGrantId(grantId);
    if (!current || current.localRole !== "grantor" || current.payload.grantor !== grantor.did) {
      throw new Error("Authoritative Grant does not exist");
    }
    if (current.payload.status === "revoked") return current;

    const identityKey = await this.accounts.getKey(grantor.id, "hail-identity");
    const resolvedGrantor = await this.resolver.resolve(grantor.did);
    if (
      resolvedGrantor.identityDidKey !== identityKey.publicKey ||
      resolvedGrantor.serviceBase !== this.expectedServiceBase
    ) {
      throw new Error("Current PLC state does not authorize this provider identity key");
    }
    const wallClock = Math.floor(this.now().getTime() / 1_000);
    const updatedAt = Math.max(wallClock, current.payload.updated_at + 1);
    if (updatedAt > wallClock + 300) throw new Error("Grant timestamp is too far ahead");
    const payload: HailGrant = {
      ...current.payload,
      revision: current.payload.revision + 1,
      previous: Uint8Array.from(current.digest),
      status: "revoked",
      updated_at: updatedAt,
      key_id: `${grantor.did}#hail-identity`,
    };
    const revision = await this.sign(grantor, identityKey, payload, resolvedGrantor.evidence);
    await this.grants.appendAuthoritativeRevocation({
      revision,
      expectedCurrentRevision: current.payload.revision,
      expectedCurrentDigest: current.digest,
    });
    return { ...revision, receivedAt: this.now() };
  }

  private async sign(
    account: AccountRecord,
    key: AccountKeyRecord,
    payload: HailGrant,
    signingPlcEvidence: PlcResolutionEvidence,
  ): Promise<SignedGrantRevisionInput> {
    if (!account.did || key.algorithm !== "ed25519") throw new Error("Invalid identity signing key");
    const privateBytes = await this.encryptor.decrypt(
      account.id,
      key.role,
      key.algorithm,
      key.publicKey,
      key,
    );
    let representation: Uint8Array;
    try {
      representation = await signPayload(
        "hail.grant",
        payload,
        createWebCryptoSigner(`${account.did}#hail-identity`, await importEd25519PrivateKey(privateBytes)),
      );
    } finally {
      privateBytes.fill(0);
    }
    const publicKey = await ed25519PublicKeyFromDidKey(key.publicKey);
    await verifySignedPayload(
      "hail.grant",
      representation,
      createWebCryptoVerifier(async (keyId) => {
        if (keyId !== `${account.did}#hail-identity`) throw new Error("Unexpected Grant key ID");
        return publicKey;
      }),
    );
    return {
      localAccountId: account.id,
      localRole: "grantor",
      payload,
      representation,
      digest: new Uint8Array(createHash("sha256").update(representation).digest()),
      signingPublicKey: key.publicKey,
      signingPlcEvidence,
    };
  }
}
