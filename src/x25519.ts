/**
 * X25519 (RFC 7748) via Node's built-in `node:crypto`.
 *
 * Used for identity-file compatibility with the other SwarmRelay tooling:
 * an identity file carries both an Ed25519 signing key and an X25519
 * encryption key. This module implements the Diffie-Hellman function and
 * PKCS#8 import/export so identities created here load in `swarmrelay
 * hello`, the TypeScript MCP server, and swarmrelay-py. E2E message
 * encryption itself is not implemented in this package (public channels
 * and tasks only); see the README for scope.
 */
import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  randomBytes,
} from "node:crypto";

// PKCS#8 DER prefix for an X25519 private key, matching WebCrypto exports.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
// SubjectPublicKeyInfo DER prefix for an X25519 public key.
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

const BASE_POINT = Buffer.concat([Buffer.from([9]), Buffer.alloc(31)]);

/** X25519(scalar, u). Both inputs are 32 bytes; output is 32 bytes. */
export function scalarmult(scalar: Buffer, uCoordinate: Buffer): Buffer {
  if (scalar.length !== 32 || uCoordinate.length !== 32) {
    throw new Error("X25519 inputs must be 32 bytes");
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, scalar]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, uCoordinate]),
    format: "der",
    type: "spki",
  });
  return diffieHellman({ privateKey, publicKey });
}

/** Generate a fresh 32-byte X25519 private scalar. */
export function generatePrivate(): Buffer {
  return randomBytes(32);
}

/** Derive the 32-byte X25519 public key from a private scalar. */
export function publicKey(privateKeyBytes: Buffer): Buffer {
  return scalarmult(privateKeyBytes, BASE_POINT);
}

/** Encode a 32-byte X25519 private scalar as PKCS#8 DER hex. */
export function privateToPkcs8Hex(privateKeyBytes: Buffer): string {
  if (privateKeyBytes.length !== 32) {
    throw new Error("X25519 private key must be 32 bytes");
  }
  return Buffer.concat([PKCS8_PREFIX, privateKeyBytes]).toString("hex");
}

/** Extract the 32-byte X25519 private scalar from a PKCS#8 DER hex. */
export function pkcs8HexToPrivate(pkcs8Hex: string): Buffer {
  const hex = pkcs8Hex.startsWith("0x") ? pkcs8Hex.slice(2) : pkcs8Hex;
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("not an X25519 PKCS#8 private key");
  }
  const raw = Buffer.from(hex, "hex");
  if (raw.length !== 48 || !raw.subarray(0, 16).equals(PKCS8_PREFIX)) {
    throw new Error("not an X25519 PKCS#8 private key");
  }
  return Buffer.from(raw.subarray(16));
}
