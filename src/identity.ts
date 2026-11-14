/**
 * Agent identity files, byte-compatible with the other SwarmRelay tooling.
 *
 * An identity file is the JSON object `swarmrelay hello`, the TypeScript
 * MCP server, and swarmrelay-py read and write at
 * `~/.swarmrelay/identity.json`:
 *
 *     {
 *       "agentId": "agent_<sha256(pubkey hex)[0..16]>",
 *       "signingPublicKey": "<64 hex, Ed25519>",
 *       "signingPrivateKey": "<96 hex, PKCS#8 DER>",
 *       "encryptionPublicKey": "<64 hex, X25519>",
 *       "encryptionPrivateKey": "<96 hex, PKCS#8 DER>"
 *     }
 *
 * Files are created with mode 0600 inside a 0700 directory. Identities
 * created here load in the other tools, and identities created there load
 * here.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import * as ed25519 from "./ed25519.js";
import { deriveAgentId } from "./envelope.js";
import * as x25519 from "./x25519.js";

export interface Identity {
  agentId: string;
  /** Hex, 32-byte Ed25519 public key. */
  signingPublicKey: string;
  /** 32-byte Ed25519 seed (kept in memory only). */
  signingSeed: Buffer;
  /** Hex, 32-byte X25519 public key. */
  encryptionPublicKey: string;
  /** 32-byte X25519 private scalar. */
  encryptionPrivate: Buffer;
}

export interface IdentityFileDict {
  agentId: string;
  signingPublicKey: string;
  signingPrivateKey: string;
  encryptionPublicKey: string;
  encryptionPrivateKey: string;
}

export const DEFAULT_IDENTITY_PATH = join(homedir(), ".swarmrelay", "identity.json");

export function identityToFileDict(identity: Identity): IdentityFileDict {
  return {
    agentId: identity.agentId,
    signingPublicKey: identity.signingPublicKey,
    signingPrivateKey: ed25519.seedToPkcs8Hex(identity.signingSeed),
    encryptionPublicKey: identity.encryptionPublicKey,
    encryptionPrivateKey: x25519.privateToPkcs8Hex(identity.encryptionPrivate),
  };
}

export function generateIdentity(): Identity {
  const seed = ed25519.generateSeed();
  const signingPublicKey = ed25519.publicKeyFromSeed(seed).toString("hex");
  const encryptionPrivate = x25519.generatePrivate();
  return {
    agentId: deriveAgentId(signingPublicKey),
    signingPublicKey,
    signingSeed: seed,
    encryptionPublicKey: x25519.publicKey(encryptionPrivate).toString("hex"),
    encryptionPrivate,
  };
}

/** Parse and validate an identity file dict (any tooling's format). */
export function identityFromFileDict(data: IdentityFileDict): Identity {
  let signingSeed: Buffer;
  let encryptionPrivate: Buffer;
  let signingPublicKey: string;
  let encryptionPublicKey: string;
  let agentId: string;
  try {
    signingSeed = ed25519.pkcs8HexToSeed(data["signingPrivateKey"]);
    encryptionPrivate = x25519.pkcs8HexToPrivate(data["encryptionPrivateKey"]);
    signingPublicKey = String(data["signingPublicKey"]).toLowerCase();
    encryptionPublicKey = String(data["encryptionPublicKey"]).toLowerCase();
    agentId = String(data["agentId"]);
  } catch (error) {
    throw new Error(`invalid identity file: ${(error as Error).message}`);
  }
  if (ed25519.publicKeyFromSeed(signingSeed).toString("hex") !== signingPublicKey) {
    throw new Error("signing public key does not match private key");
  }
  if (x25519.publicKey(encryptionPrivate).toString("hex") !== encryptionPublicKey) {
    throw new Error("encryption public key does not match private key");
  }
  if (deriveAgentId(signingPublicKey) !== agentId) {
    throw new Error("agentId does not match signing public key");
  }
  return { agentId, signingPublicKey, signingSeed, encryptionPublicKey, encryptionPrivate };
}

export function defaultIdentityPath(): string {
  return process.env["SWARM_IDENTITY"] || DEFAULT_IDENTITY_PATH;
}

export function loadIdentity(path?: string): Identity {
  const resolved = path ?? defaultIdentityPath();
  const data = JSON.parse(readFileSync(resolved, "utf-8")) as IdentityFileDict;
  return identityFromFileDict(data);
}

/** Write an identity file with 0600 permissions. Returns the path. */
export function saveIdentity(identity: Identity, path?: string): string {
  const resolved = path ?? defaultIdentityPath();
  const directory = dirname(resolved);
  if (directory) {
    mkdirSync(directory, { mode: 0o700, recursive: true });
  }
  writeFileSync(resolved, JSON.stringify(identityToFileDict(identity), null, 2) + "\n", {
    encoding: "utf-8",
    mode: 0o600,
  });
  chmodSync(resolved, 0o600);
  return resolved;
}

export function loadOrCreateIdentity(path?: string): Identity {
  const resolved = path ?? defaultIdentityPath();
  if (existsSync(resolved)) {
    return loadIdentity(resolved);
  }
  const identity = generateIdentity();
  saveIdentity(identity, resolved);
  return identity;
}
