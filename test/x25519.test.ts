import assert from "node:assert/strict";
import { describe, it } from "node:test";
import * as x25519 from "../src/x25519.js";

describe("x25519", () => {
  it("matches the RFC 7748 section 6.1 Alice public key", () => {
    const scalar = Buffer.from(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      "hex",
    );
    assert.equal(
      x25519.publicKey(scalar).toString("hex"),
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    );
  });

  it("matches the RFC 7748 section 6.1 shared secret", () => {
    // Alice's scalar with Bob's public key (RFC 7748 6.1 K value).
    const alice = Buffer.from(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      "hex",
    );
    const bobPublic = Buffer.from(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      "hex",
    );
    assert.equal(
      x25519.scalarmult(alice, bobPublic).toString("hex"),
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    );
  });

  it("Diffie-Hellman agreement holds for fresh keys", () => {
    const alicePriv = x25519.generatePrivate();
    const bobPriv = x25519.generatePrivate();
    const sharedA = x25519.scalarmult(alicePriv, x25519.publicKey(bobPriv));
    const sharedB = x25519.scalarmult(bobPriv, x25519.publicKey(alicePriv));
    assert.deepEqual(sharedA, sharedB);
  });

  it("round-trips PKCS#8 and rejects a bad prefix", () => {
    const privateKey = x25519.generatePrivate();
    const pkcs8 = x25519.privateToPkcs8Hex(privateKey);
    assert.equal(pkcs8.length, 96);
    assert.deepEqual(x25519.pkcs8HexToPrivate(pkcs8), privateKey);
    assert.throws(() => x25519.pkcs8HexToPrivate("00".repeat(48)), /not an X25519 PKCS#8/);
  });

  it("rejects wrong-length inputs", () => {
    assert.throws(() => x25519.scalarmult(Buffer.alloc(31), Buffer.alloc(32)), /32 bytes/);
    assert.throws(() => x25519.scalarmult(Buffer.alloc(32), Buffer.alloc(31)), /32 bytes/);
  });
});
