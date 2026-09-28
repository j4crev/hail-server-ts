import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import {
  createWebCryptoSigner,
  createWebCryptoVerifier,
  signPayload,
  verifySignedPayload,
  type HailSenderCategory,
  type HailSenderProfile,
} from "@hailproto/codec";
import { canonicalizeHailAddress } from "../identity/address.js";
import { ed25519PublicKeyFromDidKey } from "../identity/did-key.js";
import { importEd25519PrivateKey } from "../identity/keys.js";
import type { KeyEncryptor } from "../identity/key-encryption.js";
import type { AccountKeyRecord, AccountRecord } from "../onboarding/repository.js";
import type { HailDidResolver } from "../plc/resolver.js";
import type { StoredSenderProfile } from "./store.js";

export interface SenderProfileDefinition {
  display_name: string;
  description?: string;
  offers_uncategorized: boolean;
  categories: HailSenderCategory[];
}

export interface SenderProfileRepository {
  getAccountByAddress(canonicalAddress: string): Promise<AccountRecord>;
  getKey(accountId: string, role: AccountKeyRecord["role"]): Promise<AccountKeyRecord>;
  getLatestSenderProfile(accountId: string): Promise<StoredSenderProfile | null>;
  insertSenderProfile(
    profile: StoredSenderProfile,
    expectedPreviousRevision: number,
  ): Promise<void>;
}

function normalizedDefinition(definition: SenderProfileDefinition): SenderProfileDefinition {
  const categories = definition.categories
    .map((category) =>
      category.description === undefined
        ? { id: category.id, label: category.label }
        : { id: category.id, label: category.label, description: category.description },
    )
    .sort((left, right) => Buffer.from(left.id).compare(Buffer.from(right.id)));
  return definition.description === undefined
    ? {
        display_name: definition.display_name,
        offers_uncategorized: definition.offers_uncategorized,
        categories,
      }
    : {
        display_name: definition.display_name,
        description: definition.description,
        offers_uncategorized: definition.offers_uncategorized,
        categories,
      };
}

function matchesDefinition(
  profile: StoredSenderProfile,
  definition: SenderProfileDefinition,
  signingPublicKey: string,
): boolean {
  const payloadDefinition: SenderProfileDefinition = {
    display_name: profile.payload.display_name,
    ...(profile.payload.description === undefined
      ? {}
      : { description: profile.payload.description }),
    offers_uncategorized: profile.payload.offers_uncategorized,
    categories: profile.payload.categories,
  };
  return (
    profile.signingPublicKey === signingPublicKey &&
    isDeepStrictEqual(payloadDefinition, definition)
  );
}

export class SenderProfileService {
  constructor(
    private readonly repository: SenderProfileRepository,
    private readonly encryptor: KeyEncryptor,
    private readonly resolver: HailDidResolver,
    private readonly expectedServiceBase: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async createOrReuse(
    addressInput: string,
    inputDefinition: SenderProfileDefinition,
  ): Promise<StoredSenderProfile> {
    const address = canonicalizeHailAddress(addressInput);
    const account = await this.repository.getAccountByAddress(address);
    if (account.state !== "active" || !account.did) {
      throw new Error("Account must be active before publishing a Sender Profile");
    }
    const key = await this.repository.getKey(account.id, "hail-messaging");
    if (key.algorithm !== "ed25519") throw new Error("Hail messaging key must use Ed25519");
    const resolved = await this.resolver.resolve(account.did);
    if (
      resolved.messagingDidKey !== key.publicKey ||
      resolved.serviceBase !== this.expectedServiceBase
    ) {
      throw new Error("Current PLC state does not authorize this provider messaging key");
    }

    const definition = normalizedDefinition(inputDefinition);
    const latest = await this.repository.getLatestSenderProfile(account.id);
    if (latest && matchesDefinition(latest, definition, key.publicKey)) return latest;

    const instant = this.now();
    const current = Math.floor(instant.getTime() / 1_000);
    const updatedAt = Math.max(current, (latest?.updatedAt ?? -1) + 1);
    if (updatedAt > current + 300) throw new Error("Sender Profile timestamp is too far ahead");
    const revision = (latest?.revision ?? 0) + 1;
    const keyId = `${account.did}#hail-messaging`;
    const payload: HailSenderProfile = {
      type: "hail.sender-profile",
      version: 1,
      did: account.did,
      revision,
      display_name: definition.display_name,
      ...(definition.description === undefined ? {} : { description: definition.description }),
      offers_uncategorized: definition.offers_uncategorized,
      categories: definition.categories,
      updated_at: updatedAt,
      key_id: keyId,
    };

    const privateBytes = await this.encryptor.decrypt(
      account.id,
      key.role,
      key.algorithm,
      key.publicKey,
      key,
    );
    let cose: Uint8Array;
    try {
      const privateKey = await importEd25519PrivateKey(privateBytes);
      cose = await signPayload(
        "hail.sender-profile",
        payload,
        createWebCryptoSigner(keyId, privateKey),
      );
    } finally {
      privateBytes.fill(0);
    }
    const publicKey = await ed25519PublicKeyFromDidKey(key.publicKey);
    await verifySignedPayload(
      "hail.sender-profile",
      cose,
      createWebCryptoVerifier(async (requestedKeyId) => {
        if (requestedKeyId !== keyId) throw new Error("Unexpected Sender Profile key ID");
        return publicKey;
      }),
    );
    const profile: StoredSenderProfile = {
      id: crypto.randomUUID(),
      accountId: account.id,
      did: account.did,
      revision,
      payload,
      cose,
      digest: new Uint8Array(createHash("sha256").update(cose).digest()),
      signingPublicKey: key.publicKey,
      updatedAt,
      createdAt: instant,
    };
    try {
      await this.repository.insertSenderProfile(profile, revision - 1);
      return profile;
    } catch (error) {
      const winner = await this.repository.getLatestSenderProfile(account.id);
      if (winner && matchesDefinition(winner, definition, key.publicKey)) return winner;
      throw error;
    }
  }
}
