/**
 * SwarmRelay message envelopes and registration proofs.
 *
 * Implements the exact signing formats from @openagentforum/protocol
 * (mirroring swarmrelay-py):
 *
 * - Envelope checksum: SHA-256 hex of the canonical JSON of the payload.
 * - Envelope signature: Ed25519 over the UTF-8 bytes of
 *   `id|channel|sender|type|sequence|timestamp|checksum`.
 * - Agent ID: `agent_` + first 16 hex chars of SHA-256 of the lowercase
 *   hex-encoded public key.
 * - Profile registration (proof v2): Ed25519 over
 *   `"openagentforum:registration:v2\n" + canonical_json(document)`.
 */
import { createHash, randomUUID } from "node:crypto";
import { canonicalizeJson } from "./canonical.js";
import * as ed25519 from "./ed25519.js";

export const REGISTRATION_DOMAIN = "openagentforum:registration:v2\n";
export const REGISTRATION_MAX_AGE_MS = 5 * 60 * 1000;

export interface Envelope {
  id: string;
  channel: string;
  sender: string;
  type: string;
  sequence: number;
  timestamp: number;
  payload: unknown;
  signature: string;
  checksum: string;
  replyToId?: string;
}

export interface RegistrationProfile {
  name: string;
  x25519PublicKey: string | null;
  capabilities: string[];
  metadata: Record<string, unknown>;
  endpoint: string | null;
}

export interface RegistrationDocument {
  proofVersion: 2;
  action: "register-profile";
  hub: string;
  publicKey: string;
  expectedRevision: number;
  issuedAt: number;
  expiresAt: number;
  profile: RegistrationProfile;
}

export type SignedRegistration = RegistrationDocument & { signature: string };

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** agent_<sha256(lowercase pubkey hex)[0..16]> (hash of the hex string). */
export function deriveAgentId(publicKeyHex: string): string {
  return "agent_" + sha256Hex(publicKeyHex.toLowerCase()).slice(0, 16);
}

export function payloadChecksum(payload: unknown): string {
  return sha256Hex(canonicalizeJson(payload));
}

export function envelopeSignString(parts: {
  envelopeId: string;
  channel: string;
  sender: string;
  type: string;
  sequence: number;
  timestamp: number;
  checksum: string;
}): string {
  return [
    parts.envelopeId,
    parts.channel,
    parts.sender,
    parts.type,
    parts.sequence,
    parts.timestamp,
    parts.checksum,
  ].join("|");
}

/** Build and sign a message envelope. Returns the envelope object. */
export function signEnvelope(options: {
  seed: Buffer;
  sender: string;
  channel: string;
  type: string;
  payload: unknown;
  sequence?: number;
  timestamp?: number;
  envelopeId?: string;
  replyToId?: string;
}): Envelope {
  const envelopeId = options.envelopeId ?? randomUUID();
  const timestamp = options.timestamp ?? Date.now();
  const sequence = options.sequence ?? 0;
  const checksum = payloadChecksum(options.payload);
  const signString = envelopeSignString({
    envelopeId,
    channel: options.channel,
    sender: options.sender,
    type: options.type,
    sequence,
    timestamp,
    checksum,
  });
  const signature = ed25519.sign(options.seed, Buffer.from(signString, "utf-8")).toString("hex");
  const envelope: Envelope = {
    id: envelopeId,
    channel: options.channel,
    sender: options.sender,
    type: options.type,
    sequence,
    timestamp,
    payload: options.payload,
    signature,
    checksum,
  };
  if (options.replyToId !== undefined) {
    envelope.replyToId = options.replyToId;
  }
  return envelope;
}

function hexToBuffer(hex: string): Buffer {
  if (!/^(0x)?[0-9a-fA-F]*$/.test(hex) || hex.replace(/^0x/, "").length % 2 !== 0) {
    throw new Error("invalid hex string");
  }
  return Buffer.from(hex.replace(/^0x/, ""), "hex");
}

/** Verify an envelope's checksum, sender binding and signature. */
export function verifyEnvelope(
  envelope: Record<string, unknown>,
  publicKeyHex: string,
): { valid: boolean; error: string | null } {
  try {
    const payload = envelope["payload"];
    if (payloadChecksum(payload) !== String(envelope["checksum"]).toLowerCase()) {
      return { valid: false, error: "payload checksum mismatch" };
    }
    const expectedSender = deriveAgentId(publicKeyHex);
    if (String(envelope["sender"]).toLowerCase() !== expectedSender.toLowerCase()) {
      return { valid: false, error: "sender does not match public key fingerprint" };
    }
    const signString = envelopeSignString({
      envelopeId: envelope["id"] as string,
      channel: envelope["channel"] as string,
      sender: envelope["sender"] as string,
      type: envelope["type"] as string,
      sequence: envelope["sequence"] as number,
      timestamp: envelope["timestamp"] as number,
      checksum: envelope["checksum"] as string,
    });
    const valid = ed25519.verify(
      hexToBuffer(publicKeyHex),
      Buffer.from(signString, "utf-8"),
      hexToBuffer(String(envelope["signature"])),
    );
    return valid ? { valid: true, error: null } : { valid: false, error: "invalid Ed25519 signature" };
  } catch (error) {
    return { valid: false, error: `malformed envelope: ${(error as Error).message}` };
  }
}

/** Build the v2 profile-registration document (unsigned). */
export function buildRegistrationDocument(options: {
  hubOrigin: string;
  publicKeyHex: string;
  expectedRevision: number;
  name: string;
  x25519PublicKeyHex: string | null;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  endpoint?: string | null;
  issuedAt?: number;
}): RegistrationDocument {
  const issuedAt = options.issuedAt ?? Date.now();
  return {
    proofVersion: 2,
    action: "register-profile",
    hub: options.hubOrigin,
    publicKey: options.publicKeyHex.toLowerCase(),
    expectedRevision: options.expectedRevision,
    issuedAt,
    expiresAt: issuedAt + REGISTRATION_MAX_AGE_MS,
    profile: {
      name: options.name,
      x25519PublicKey: options.x25519PublicKeyHex
        ? options.x25519PublicKeyHex.toLowerCase()
        : null,
      capabilities: options.capabilities ?? [],
      metadata: options.metadata ?? {},
      endpoint: options.endpoint ?? null,
    },
  };
}

/** Sign a registration document. Returns the document plus `signature`. */
export function signRegistration(document: RegistrationDocument, seed: Buffer): SignedRegistration {
  const message = Buffer.from(REGISTRATION_DOMAIN + canonicalizeJson(document), "utf-8");
  return { ...document, signature: ed25519.sign(seed, message).toString("hex") };
}

export function registrationDigest(signedRegistration: SignedRegistration): string {
  return sha256Hex(REGISTRATION_DOMAIN + canonicalizeJson(signedRegistration));
}
