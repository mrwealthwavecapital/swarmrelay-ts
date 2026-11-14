import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  generateIdentity,
  identityFromFileDict,
  identityToFileDict,
  loadIdentity,
  saveIdentity,
} from "../src/identity.js";

describe("identity", () => {
  it("round-trips through the file dict", () => {
    const identity = generateIdentity();
    const restored = identityFromFileDict(identityToFileDict(identity));
    assert.equal(restored.agentId, identity.agentId);
    assert.deepEqual(restored.signingSeed, identity.signingSeed);
    assert.deepEqual(restored.encryptionPrivate, identity.encryptionPrivate);
  });

  it("derives the agent id from the signing public key", () => {
    const identity = generateIdentity();
    const expected =
      "agent_" +
      createHash("sha256").update(identity.signingPublicKey.toLowerCase()).digest("hex").slice(0, 16);
    assert.equal(identity.agentId, expected);
  });

  it("rejects a mismatched signing public key", () => {
    const identity = generateIdentity();
    const data = identityToFileDict(identity);
    data.signingPublicKey = generateIdentity().signingPublicKey;
    assert.throws(() => identityFromFileDict(data), /does not match/);
  });

  it("rejects a mismatched encryption public key", () => {
    const identity = generateIdentity();
    const data = identityToFileDict(identity);
    data.encryptionPublicKey = generateIdentity().encryptionPublicKey;
    assert.throws(() => identityFromFileDict(data), /does not match/);
  });

  it("rejects a mismatched agent id", () => {
    const identity = generateIdentity();
    const data = identityToFileDict(identity);
    data.agentId = generateIdentity().agentId;
    assert.throws(() => identityFromFileDict(data), /does not match/);
  });

  it("rejects a bad private key encoding", () => {
    const identity = generateIdentity();
    const data = identityToFileDict(identity);
    data.signingPrivateKey = "00".repeat(48);
    assert.throws(() => identityFromFileDict(data), /invalid identity file/);
  });

  it("saves and loads with 0600 permissions", () => {
    const dir = mkdtempSync(join(tmpdir(), "swarmrelay-ts-identity-"));
    const path = join(dir, "nested", "identity.json");
    const identity = generateIdentity();
    saveIdentity(identity, path);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    const loaded = loadIdentity(path);
    assert.equal(loaded.agentId, identity.agentId);
    assert.deepEqual(loaded.signingSeed, identity.signingSeed);
  });
});
