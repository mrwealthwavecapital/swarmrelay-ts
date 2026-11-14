/**
 * Ed25519 (RFC 8032) via Node's built-in WebCrypto-compatible `node:crypto`.
 *
 * This is the same primitive the reference TypeScript implementation uses,
 * so signatures here are byte-identical to signatures from swarmrelay-py
 * (which implements the curve in pure Python) and from `swarmrelay` itself.
 * Ed25519 signing is deterministic: the same seed + message always yields
 * the same signature, which is what makes the cross-implementation vectors
 * in the test suite exact.
 *
 * Private keys are handled as 32-byte seeds. PKCS#8 DER import/export
 * matches the identity-file format used by `swarmrelay hello`, the
 * TypeScript MCP server, and swarmrelay-py, so identities created here load
 * in all three and vice versa.
 */
import {
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

// PKCS#8 DER prefix for an Ed25519 private key: the 16-byte header followed
// by the 32-byte seed. This is the exact structure WebCrypto exports.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
// SubjectPublicKeyInfo DER prefix for an Ed25519 public key, followed by
// the 32-byte raw public key.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function privateKeyFromSeed(seed: Buffer): KeyObject {
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyObject(publicKey: Buffer): KeyObject {
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
}

/** Generate a fresh 32-byte Ed25519 seed. */
export function generateSeed(): Buffer {
  return randomBytes(32);
}

/** Derive the 32-byte encoded public key from a 32-byte seed. */
export function publicKeyFromSeed(seed: Buffer): Buffer {
  const spki = createPublicKey(privateKeyFromSeed(seed)).export({
    type: "spki",
    format: "der",
  });
  const raw = Buffer.from(spki);
  return raw.subarray(raw.length - 32);
}

/** Sign a message. Returns the 64-byte signature (R || S). */
export function sign(seed: Buffer, message: Buffer): Buffer {
  return cryptoSign(null, message, privateKeyFromSeed(seed));
}

/**
 * Verify a 64-byte signature against a 32-byte public key.
 * Returns false (never throws) for malformed keys or signatures.
 */
export function verify(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }
  try {
    return cryptoVerify(null, message, publicKeyObject(publicKey), signature);
  } catch {
    return false;
  }
}

/** Encode a 32-byte seed as a PKCS#8 DER hex string (WebCrypto format). */
export function seedToPkcs8Hex(seed: Buffer): string {
  if (seed.length !== 32) {
    throw new Error("seed must be 32 bytes");
  }
  return Buffer.concat([PKCS8_PREFIX, seed]).toString("hex");
}

/** Extract the 32-byte seed from a PKCS#8 DER hex string. */
export function pkcs8HexToSeed(pkcs8Hex: string): Buffer {
  const hex = pkcs8Hex.startsWith("0x") ? pkcs8Hex.slice(2) : pkcs8Hex;
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error("not an Ed25519 PKCS#8 private key");
  }
  const raw = Buffer.from(hex, "hex");
  if (raw.length !== 48 || !raw.subarray(0, 16).equals(PKCS8_PREFIX)) {
    throw new Error("not an Ed25519 PKCS#8 private key");
  }
  return Buffer.from(raw.subarray(16));
}
