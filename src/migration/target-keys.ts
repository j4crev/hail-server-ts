import { randomUUID } from "node:crypto";
import { P256Keypair } from "@atproto/crypto";
import { base58btc } from "multiformats/bases/base58";
import type { SQL } from "bun";
import { ed25519PublicKeyFromDidKey } from "../identity/did-key.js";
import type { KeyEncryptor } from "../identity/key-encryption.js";
import { importEd25519PrivateKey } from "../identity/keys.js";
import type { HailDidResolver } from "../plc/resolver.js";
import { handshakeDigest, sameDigest, signHandshake, verifyHandshake,
  type SignedHandshake, type TransferRequest, type TransferGrant, type TransferInvitation,
  type TransferOffer, type TransferAddressSelection, type TransferReservation } from "./handshake.js";

export interface PreparedTargetKeys {
  transferId: string;
  did: string;
  destinationServiceBase: string;
  rotationPublicKey: string;
  messagingPublicKey: string;
}

interface TargetKeyRow {
  did: string;
  destination_service_base: string;
  rotation_public_key: string;
  rotation_private_ciphertext: Uint8Array;
  rotation_nonce: Uint8Array;
  messaging_public_key: string;
  messaging_private_ciphertext: Uint8Array;
  messaging_nonce: Uint8Array;
  state: string;
}

export class PreparedMigrationTarget {
  constructor(
    private readonly sql: SQL,
    private readonly encryptor: KeyEncryptor,
    private readonly destinationServiceBase: string,
  ) {}

  async prepare(did: string): Promise<PreparedTargetKeys> {
    if (!/^did:plc:[a-z2-7]{24}$/.test(did)) throw new Error("Target DID is not canonical");
    const existing = await this.sql<{ id: string }[]>`SELECT id FROM provider_accounts WHERE did = ${did}`;
    if (existing.length) throw new Error("Target already serves this DID");
    const transferId = randomUUID();
    const rotation = await P256Keypair.create({ exportable: true });
    const messaging = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
    const prefixed = new Uint8Array(34);
    prefixed.set([0xed, 0x01]);
    prefixed.set(new Uint8Array(await crypto.subtle.exportKey("raw", messaging.publicKey)), 2);
    const rotationPublicKey = rotation.did();
    const messagingPublicKey = `did:key:${base58btc.encode(prefixed)}`;
    const rotationBytes = new Uint8Array(await rotation.export());
    const messagingBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", messaging.privateKey));
    let encryptedRotation;
    let encryptedMessaging;
    try {
      [encryptedRotation, encryptedMessaging] = await Promise.all([
        this.encryptor.encrypt(transferId, "plc-rotation", "p256", rotationPublicKey, rotationBytes),
        this.encryptor.encrypt(transferId, "hail-messaging", "ed25519", messagingPublicKey, messagingBytes),
      ]);
    } finally {
      rotationBytes.fill(0);
      messagingBytes.fill(0);
    }
    await this.sql`
      INSERT INTO prepared_migration_target_keys
        (transfer_id, did, destination_service_base, rotation_public_key,
         rotation_private_ciphertext, rotation_nonce, messaging_public_key,
         messaging_private_ciphertext, messaging_nonce)
      VALUES (${transferId}, ${did}, ${this.destinationServiceBase}, ${rotationPublicKey},
        ${encryptedRotation.ciphertext}, ${encryptedRotation.nonce}, ${messagingPublicKey},
        ${encryptedMessaging.ciphertext}, ${encryptedMessaging.nonce})
    `;
    return { transferId, did, destinationServiceBase: this.destinationServiceBase,
      rotationPublicKey, messagingPublicKey };
  }

  async validateInvitation(did: string, grantSigned: SignedHandshake,
    invitationSigned: SignedHandshake, resolver: HailDidResolver):
    Promise<{ grant: TransferGrant; invitation: TransferInvitation }> {
    const state = await resolver.resolve(did);
    const grant = await verifyHandshake(grantSigned, "hail.transfer-grant", state.identityDidKey);
    const invitation = await verifyHandshake(invitationSigned, "hail.transfer-invitation", state.messagingDidKey);
    const now = Math.floor(Date.now() / 1000);
    if (state.did !== did || state.serviceBase !== grant.source_service_base ||
      grant.did !== did || invitation.did !== grant.did || invitation.nonce !== grant.nonce ||
      invitation.source_service_base !== grant.source_service_base ||
      invitation.destination_service_base !== grant.destination_service_base ||
      grant.destination_service_base !== this.destinationServiceBase ||
      invitation.expires_at !== grant.expires_at || grant.expires_at <= now ||
      !sameDigest(invitation.grant_digest, handshakeDigest(grantSigned.payloadBytes))) {
      throw new Error("Destination invitation does not match the user grant");
    }
    return { grant, invitation };
  }

  async createOffer(prepared: PreparedTargetKeys, grantSigned: SignedHandshake,
    invitationSigned: SignedHandshake, resolver: HailDidResolver): Promise<SignedHandshake> {
    const { grant, invitation } = await this.validateInvitation(prepared.did, grantSigned, invitationSigned, resolver);
    const now = Math.floor(Date.now() / 1000);
    const offer: TransferOffer = { type: "hail.transfer-offer", version: 1,
      did: prepared.did, nonce: grant.nonce, transfer_id: prepared.transferId,
      source_service_base: grant.source_service_base,
      destination_service_base: grant.destination_service_base,
      grant_digest: handshakeDigest(grantSigned.payloadBytes),
      invitation_digest: handshakeDigest(invitationSigned.payloadBytes),
      invitation_challenge: invitation.challenge,
      destination_rotation_key: prepared.rotationPublicKey,
      destination_messaging_key: prepared.messagingPublicKey,
      issued_at: now, expires_at: grant.expires_at };
    return this.signWithPreparedMessaging(prepared, offer);
  }

  async finalRequest(prepared: PreparedTargetKeys, offerSigned: SignedHandshake,
    selectionSigned: SignedHandshake, receiptSigned: SignedHandshake,
    userIdentityKey: string): Promise<SignedHandshake> {
    const offer = await verifyHandshake(offerSigned, "hail.transfer-offer", prepared.messagingPublicKey);
    const selection = await verifyHandshake(selectionSigned, "hail.transfer-address-selection",
      userIdentityKey);
    const receipt = await verifyHandshake(receiptSigned, "hail.transfer-reservation", prepared.messagingPublicKey);
    if (offer.did !== prepared.did || offer.transfer_id !== prepared.transferId ||
      offer.destination_messaging_key !== prepared.messagingPublicKey ||
      selection.did !== offer.did || selection.transfer_id !== offer.transfer_id ||
      selection.nonce !== offer.nonce ||
      !sameDigest(selection.grant_digest, offer.grant_digest) ||
      receipt.did !== offer.did || receipt.transfer_id !== offer.transfer_id ||
      receipt.nonce !== offer.nonce ||
      receipt.address !== selection.address ||
      !sameDigest(selection.offer_digest, handshakeDigest(offerSigned.payloadBytes)) ||
      !sameDigest(receipt.offer_digest, handshakeDigest(offerSigned.payloadBytes)) ||
      !sameDigest(receipt.selection_digest, handshakeDigest(selectionSigned.payloadBytes))) {
      throw new Error("Final request does not match the address reservation");
    }
    const now = Math.floor(Date.now() / 1000);
    if (selection.expires_at <= now || receipt.expires_at <= now || offer.expires_at <= now) {
      throw new Error("Transfer address reservation has expired");
    }
    const request: TransferRequest = { ...offer, type: "hail.transfer-request", version: 1,
      offer_digest: handshakeDigest(offerSigned.payloadBytes),
      destination_address: selection.address,
      selection_digest: handshakeDigest(selectionSigned.payloadBytes),
      reservation_digest: handshakeDigest(receiptSigned.payloadBytes),
      issued_at: now, expires_at: Math.min(now + 300, offer.expires_at) };
    return this.signWithPreparedMessaging(prepared, request);
  }

  private async signWithPreparedMessaging(prepared: PreparedTargetKeys,
    value: TransferOffer | TransferRequest | TransferReservation): Promise<SignedHandshake> {
    await this.assertOwnership(prepared);
    const rows = await this.sql<TargetKeyRow[]>`
      SELECT messaging_public_key, messaging_private_ciphertext, messaging_nonce
      FROM prepared_migration_target_keys WHERE transfer_id = ${prepared.transferId}`;
    const row = rows[0];
    if (!row || row.messaging_public_key !== prepared.messagingPublicKey) throw new Error("Target key missing");
    const keyBytes = await this.encryptor.decrypt(prepared.transferId, "hail-messaging", "ed25519",
      row.messaging_public_key, { ciphertext: row.messaging_private_ciphertext,
        nonce: row.messaging_nonce, encryptionVersion: 1, kekId: "poc-v1" });
    try { return await signHandshake(value, await importEd25519PrivateKey(keyBytes)); }
    finally { keyBytes.fill(0); }
  }

  async signReservation(prepared: PreparedTargetKeys, value: TransferReservation): Promise<SignedHandshake> {
    return this.signWithPreparedMessaging(prepared, value);
  }

  async assertOwnership(expected: PreparedTargetKeys): Promise<void> {
    const rows = await this.sql<TargetKeyRow[]>`
      SELECT did, destination_service_base, rotation_public_key, rotation_private_ciphertext,
        rotation_nonce, messaging_public_key, messaging_private_ciphertext, messaging_nonce, state
      FROM prepared_migration_target_keys WHERE transfer_id = ${expected.transferId}
    `;
    const row = rows[0];
    if (!row || !["prepared", "staged"].includes(row.state) ||
      row.did !== expected.did || row.destination_service_base !== expected.destinationServiceBase ||
      row.rotation_public_key !== expected.rotationPublicKey ||
      row.messaging_public_key !== expected.messagingPublicKey) {
      throw new Error("Destination does not own the requested prepared operational keys");
    }
    const rotation = await this.encryptor.decrypt(expected.transferId, "plc-rotation", "p256", row.rotation_public_key, {
      ciphertext: row.rotation_private_ciphertext, nonce: row.rotation_nonce, encryptionVersion: 1, kekId: "poc-v1",
    });
    const messaging = await this.encryptor.decrypt(expected.transferId, "hail-messaging", "ed25519", row.messaging_public_key, {
      ciphertext: row.messaging_private_ciphertext, nonce: row.messaging_nonce, encryptionVersion: 1, kekId: "poc-v1",
    });
    try {
      if ((await P256Keypair.import(rotation)).did() !== row.rotation_public_key) {
        throw new Error("Destination rotation private key does not match its public DID key");
      }
      const privateKey = await importEd25519PrivateKey(messaging);
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const signature = await crypto.subtle.sign("Ed25519", privateKey, challenge);
      if (!await crypto.subtle.verify("Ed25519", await ed25519PublicKeyFromDidKey(row.messaging_public_key),
        signature, challenge)) {
        throw new Error("Destination messaging private key does not match its public DID key");
      }
    } finally { rotation.fill(0); messaging.fill(0); }
  }
}
