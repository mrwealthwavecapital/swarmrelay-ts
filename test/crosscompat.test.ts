/**
 * Cross-implementation vectors generated with swarmrelay-py (pure-Python
 * Ed25519/X25519) from fixed throwaway seeds. The identity below was never
 * registered and never posted; it exists only so the two implementations
 * can prove byte-compatibility offline.
 *
 * Ed25519 is deterministic, so re-signing the same fields in TypeScript
 * must reproduce the Python signatures byte for byte.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canonicalizeJson } from "../src/canonical.js";
import * as ed25519 from "../src/ed25519.js";
import * as env from "../src/envelope.js";
import { identityFromFileDict } from "../src/identity.js";
import * as x25519 from "../src/x25519.js";

// Signing seed: bytes 0..31. Encryption scalar: RFC 7748 Alice.
const PYTHON_IDENTITY = {
  agentId: "agent_25f578ee40fd903d",
  signingPublicKey: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  signingPrivateKey:
    "302e020100300506032b657004220420000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  encryptionPublicKey: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  encryptionPrivateKey:
    "302e020100300506032b656e0422042077076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
};

const PYTHON_ENVELOPE = {
  id: "00000000-0000-0000-0000-000000000001",
  channel: "general",
  sender: "agent_25f578ee40fd903d",
  type: "intel",
  sequence: 7,
  timestamp: 1794432000000,
  payload: { message: "hello from python" },
  signature:
    "ed0ae686c6d67534ee03fa8f82d13b844e828594a763eb45f706efe29a22f6434ccfecf166857c0251272bc2d191b724bccbf00e58b8e1b3f7d0309d6aeb5b02",
  checksum: "36cdfe702b76cd620bd3b07e2196cd27ac1eae838dcf9211887f48ff2b31937a",
};

const PYTHON_SIGN_STRING =
  "00000000-0000-0000-0000-000000000001|general|agent_25f578ee40fd903d|intel|7|1794432000000|36cdfe702b76cd620bd3b07e2196cd27ac1eae838dcf9211887f48ff2b31937a";

const PYTHON_REGISTRATION = {
  proofVersion: 2,
  action: "register-profile",
  hub: "https://openagentforum.com",
  publicKey: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  expectedRevision: 3,
  issuedAt: 1794432000000,
  expiresAt: 1794432300000,
  profile: {
    name: "crosscheck-agent",
    x25519PublicKey: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    capabilities: ["typescript"],
    metadata: {},
    endpoint: null,
  },
};

const PYTHON_REGISTRATION_SIGNATURE =
  "32eae6508e353825d23e790fe988b9d6cb16c34af16f18632ed1081c14c5f9264bdbf12825ef5af9b879cd5c88ff396bd9c200562619b567fc4ed7620c3dab0f";

describe("cross-compat with swarmrelay-py", () => {
  it("loads a Python-generated identity file", () => {
    const identity = identityFromFileDict(PYTHON_IDENTITY);
    assert.equal(identity.agentId, "agent_25f578ee40fd903d");
    assert.equal(identity.signingSeed.toString("hex"), "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    assert.equal(
      identity.encryptionPrivate.toString("hex"),
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    );
  });

  it("reproduces the Python envelope sign string", () => {
    assert.equal(
      env.envelopeSignString({
        envelopeId: PYTHON_ENVELOPE.id,
        channel: PYTHON_ENVELOPE.channel,
        sender: PYTHON_ENVELOPE.sender,
        type: PYTHON_ENVELOPE.type,
        sequence: PYTHON_ENVELOPE.sequence,
        timestamp: PYTHON_ENVELOPE.timestamp,
        checksum: PYTHON_ENVELOPE.checksum,
      }),
      PYTHON_SIGN_STRING,
    );
  });

  it("verifies a Python-signed envelope", () => {
    const { valid, error } = env.verifyEnvelope(
      PYTHON_ENVELOPE as unknown as Record<string, unknown>,
      PYTHON_IDENTITY.signingPublicKey,
    );
    assert.equal(valid, true, error ?? "verification failed");
  });

  it("re-signs the same envelope fields to the identical signature", () => {
    const identity = identityFromFileDict(PYTHON_IDENTITY);
    const resigned = env.signEnvelope({
      seed: identity.signingSeed,
      sender: PYTHON_ENVELOPE.sender,
      channel: PYTHON_ENVELOPE.channel,
      type: PYTHON_ENVELOPE.type,
      payload: PYTHON_ENVELOPE.payload,
      sequence: PYTHON_ENVELOPE.sequence,
      timestamp: PYTHON_ENVELOPE.timestamp,
      envelopeId: PYTHON_ENVELOPE.id,
    });
    assert.equal(resigned.signature, PYTHON_ENVELOPE.signature);
    assert.equal(resigned.checksum, PYTHON_ENVELOPE.checksum);
  });

  it("verifies a Python-signed v2 registration proof", () => {
    const message = Buffer.from(
      env.REGISTRATION_DOMAIN + canonicalizeJson(PYTHON_REGISTRATION),
      "utf-8",
    );
    assert.equal(
      ed25519.verify(
        Buffer.from(PYTHON_IDENTITY.signingPublicKey, "hex"),
        message,
        Buffer.from(PYTHON_REGISTRATION_SIGNATURE, "hex"),
      ),
      true,
    );
  });

  it("re-signs the same registration document to the identical signature", () => {
    const identity = identityFromFileDict(PYTHON_IDENTITY);
    const rebuilt = env.buildRegistrationDocument({
      hubOrigin: "https://openagentforum.com",
      publicKeyHex: identity.signingPublicKey,
      expectedRevision: 3,
      name: "crosscheck-agent",
      x25519PublicKeyHex: identity.encryptionPublicKey,
      capabilities: ["typescript"],
      issuedAt: 1794432000000,
    });
    assert.equal(canonicalizeJson(rebuilt), canonicalizeJson(PYTHON_REGISTRATION));
    const signed = env.signRegistration(rebuilt, identity.signingSeed);
    assert.equal(signed.signature, PYTHON_REGISTRATION_SIGNATURE);
  });

  it("agrees with Python on the X25519 shared secret", () => {
    const identity = identityFromFileDict(PYTHON_IDENTITY);
    const bobPublic = Buffer.from(
      "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254",
      "hex",
    );
    assert.equal(
      x25519.scalarmult(identity.encryptionPrivate, bobPublic).toString("hex"),
      "2bac4251e94db22ab2507599c7692ec2b2136b3a4fcac551f71bbd26e0a8ce4a",
    );
  });
});
