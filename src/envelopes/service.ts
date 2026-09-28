import { createHash } from "node:crypto";
import {
  createWebCryptoSigner, createWebCryptoVerifier, decodeBase64Url, encodeBase64Url,
  inspectSignedPayload, signPayload, verifySignedPayload, type HailEnvelope,
} from "@hailproto/codec";
import { newBodyToken } from "../bodies/service.js";
import type { GrantStore } from "../grants/store.js";
import { ed25519PublicKeyFromDidKey } from "../identity/did-key.js";
import type { KeyEncryptor } from "../identity/key-encryption.js";
import { importEd25519PrivateKey } from "../identity/keys.js";
import { uuidV7 } from "../identity/uuid-v7.js";
import type { AccountKeyRecord, AccountRecord } from "../onboarding/repository.js";
import type { HailDidResolver } from "../plc/resolver.js";
import type { EnvelopeRepository } from "./repository.js";

export interface SenderAccounts {
  getAccountByDid(did: string): Promise<AccountRecord | null>;
  getKey(accountId: string, role: AccountKeyRecord["role"]): Promise<AccountKeyRecord>;
}

export interface CreatedEnvelope {
  payload: HailEnvelope;
  representation: Uint8Array;
  digest: Uint8Array;
  destination: string;
}

export class EnvelopeService {
  constructor(
    private readonly accounts: SenderAccounts,
    private readonly grants: Pick<GrantStore, "findCurrentByGrantId">,
    private readonly envelopes: Pick<EnvelopeRepository, "publishedBody" | "createSent">,
    private readonly encryptor: KeyEncryptor,
    private readonly resolver: HailDidResolver,
    private readonly serviceBase: string,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  async create(senderDid: string, grantId: string, digestText: string, category: string): Promise<CreatedEnvelope> {
    const account = await this.accounts.getAccountByDid(senderDid);
    if (!account || account.state !== "active" || account.activationVerificationMode !== "public") {
      throw new Error("Sender requires public activation");
    }
    const grant = await this.grants.findCurrentByGrantId(grantId);
    const now = this.now();
    if (!grant || grant.localRole !== "grantee" || grant.payload.status !== "active" ||
      grant.payload.grantee !== senderDid || (grant.payload.expires_at !== null && grant.payload.expires_at < now)) {
      throw new Error("No active received Grant for this sender");
    }
    const scope = grant.payload.scope[0];
    if (!scope || (scope.type === "categories" && !scope.values.includes(category)) ||
      (scope.type === "uncategorized" && category !== "")) throw new Error("Category is outside Grant scope");
    const digest = decodeBase64Url(digestText);
    if (digest.length !== 32 || encodeBase64Url(digest) !== digestText) throw new Error("Invalid body digest");
    const body = await this.envelopes.publishedBody(senderDid, digest);
    if (!body || body.senderAccountId !== account.id) throw new Error("Body must exist before envelope signing");
    const sender = await this.resolver.resolve(senderDid);
    const recipient = await this.resolver.resolve(grant.payload.grantor);
    const key = await this.accounts.getKey(account.id, "hail-messaging");
    if (sender.messagingDidKey !== key.publicKey || sender.serviceBase !== this.serviceBase || key.algorithm !== "ed25519") {
      throw new Error("Current PLC state does not authorize the local messaging key");
    }
    const availableUntil = now + 31 * 86400;
    const payload: HailEnvelope = {
      type: "hail.envelope", version: 1, message_id: uuidV7(now * 1000),
      from: senderDid, to: grant.payload.grantor,
      authorization: { type: "grant", grant_id: grantId },
      ...(category ? { category } : {}),
      created_at: now, expires_at: now + 7 * 86400,
      body: {
        digest: { algorithm: "sha-256", value: new Uint8Array(digest) }, size: body.size,
        media_type: "application/hail-body+cbor", profile: "spt-1", available_until: availableUntil,
        access: { type: "bearer", token: newBodyToken(), expires_at: availableUntil },
      },
      reply: { allowed: false },
    };
    const secret = await this.encryptor.decrypt(account.id, key.role, key.algorithm, key.publicKey, key);
    let representation: Uint8Array;
    try {
      representation = await signPayload("hail.envelope", payload,
        createWebCryptoSigner(`${senderDid}#hail-messaging`, await importEd25519PrivateKey(secret)));
    } finally { secret.fill(0); }
    await verifySignedPayload("hail.envelope", representation,
      createWebCryptoVerifier(async (kid) => {
        if (kid !== `${senderDid}#hail-messaging`) throw new Error("Invalid envelope signer");
        return ed25519PublicKeyFromDidKey(key.publicKey);
      }));
    if (representation.length > 16_384) throw new Error("Signed envelope exceeds 16 KiB");
    await this.envelopes.createSent(payload, representation, account.id);
    return { payload, representation,
      digest: new Uint8Array(createHash("sha256").update(inspectSignedPayload("hail.envelope", representation).payloadBytes).digest()),
      destination: `${recipient.serviceBase}/envelopes` };
  }
}
