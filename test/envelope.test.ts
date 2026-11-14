import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { canonicalizeJson } from "../src/canonical.js";
import * as ed25519 from "../src/ed25519.js";
import * as env from "../src/envelope.js";
import { generateIdentity } from "../src/identity.js";

describe("envelope", () => {
  it("sign/verify round-trips with a fixed checksum", () => {
    const identity = generateIdentity();
    const signed = env.signEnvelope({
      seed: identity.signingSeed,
      sender: identity.agentId,
      channel: "general",
      type: "intel",
      payload: { message: "hello" },
      sequence: 0,
      timestamp: 1794432000000,
      envelopeId: "00000000-0000-0000-0000-000000000001",
    });
    assert.equal(
      signed.checksum,
      createHash("sha256").update('{"message":"hello"}').digest("hex"),
    );
    const { valid, error } = env.verifyEnvelope(
      signed as unknown as Record<string, unknown>,
      identity.signingPublicKey,
    );
    assert.equal(valid, true, error ?? "verification failed");
  });

  it("detects payload tampering", () => {
    const identity = generateIdentity();
    const signed = env.signEnvelope({
      seed: identity.signingSeed,
      sender: identity.agentId,
      channel: "general",
      type: "intel",
      payload: { message: "hello" },
    });
    const tampered = { ...signed, payload: { message: "forged" } };
    const { valid } = env.verifyEnvelope(
      tampered as unknown as Record<string, unknown>,
      identity.signingPublicKey,
    );
    assert.equal(valid, false);
  });

  it("detects a sender that does not match the public key", () => {
    const identity = generateIdentity();
    const other = generateIdentity();
    const signed = env.signEnvelope({
      seed: identity.signingSeed,
      sender: identity.agentId,
      channel: "general",
      type: "intel",
      payload: { message: "hello" },
    });
    const { valid, error } = env.verifyEnvelope(
      signed as unknown as Record<string, unknown>,
      other.signingPublicKey,
    );
    assert.equal(valid, false);
    assert.match(error ?? "", /sender does not match/);
  });

  it("carries replyToId only when given", () => {
    const identity = generateIdentity();
    const plain = env.signEnvelope({
      seed: identity.signingSeed,
      sender: identity.agentId,
      channel: "general",
      type: "intel",
      payload: {},
    });
    assert.equal("replyToId" in plain, false);
    const reply = env.signEnvelope({
      seed: identity.signingSeed,
      sender: identity.agentId,
      channel: "general",
      type: "intel",
      payload: {},
      replyToId: "abc",
    });
    assert.equal(reply.replyToId, "abc");
  });

  it("signs the v2 registration document under the documented domain", () => {
    const identity = generateIdentity();
    const document = env.buildRegistrationDocument({
      hubOrigin: "https://openagentforum.com",
      publicKeyHex: identity.signingPublicKey,
      expectedRevision: 0,
      name: "test-agent",
      x25519PublicKeyHex: identity.encryptionPublicKey,
      capabilities: ["typescript"],
    });
    assert.equal(document.expiresAt - document.issuedAt, env.REGISTRATION_MAX_AGE_MS);
    const signed = env.signRegistration(document, identity.signingSeed);
    assert.equal(signed.signature.length, 128);
    const message = Buffer.from(env.REGISTRATION_DOMAIN + canonicalizeJson(document), "utf-8");
    assert.equal(
      ed25519.verify(
        Buffer.from(identity.signingPublicKey, "hex"),
        message,
        Buffer.from(signed.signature, "hex"),
      ),
      true,
    );
  });

  it("builds the registration document with nulls for missing fields", () => {
    const identity = generateIdentity();
    const document = env.buildRegistrationDocument({
      hubOrigin: "https://openagentforum.com",
      publicKeyHex: identity.signingPublicKey,
      expectedRevision: 3,
      name: "n",
      x25519PublicKeyHex: null,
      issuedAt: 1794432000000,
    });
    assert.equal(document.profile.x25519PublicKey, null);
    assert.equal(document.profile.endpoint, null);
    assert.deepEqual(document.profile.capabilities, []);
    assert.deepEqual(document.profile.metadata, {});
    assert.equal(document.expiresAt, 1794432300000);
  });
});
