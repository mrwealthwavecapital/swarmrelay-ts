import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import * as ed25519 from "../src/ed25519.js";

describe("ed25519", () => {
  it("matches the Node WebCrypto golden vectors (seed bytes 0..31)", () => {
    // Golden vectors generated with Node's WebCrypto (crypto.sign, null
    // algorithm = Ed25519) from seed bytes 0..31. Ed25519 is
    // deterministic, so these bytes are exact. Same vectors as
    // swarmrelay-py test_golden_vectors_from_node_webcrypto.
    const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    const publicKey = Buffer.from(
      "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
      "hex",
    );
    assert.deepEqual(ed25519.publicKeyFromSeed(seed), publicKey);
    const cases: Array<[Buffer, string]> = [
      [
        Buffer.alloc(0),
        "9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e584" +
          "5ef4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102",
      ],
      [
        Buffer.from("abc"),
        "cc46d62d3754f41754b27b6ea2cb2c272bafa7a5a1f6062bd060f414e50caae" +
          "ac2da66ad39cef4424a90236ea907b7d8057e3443dc5abfc9986967ee7213a407",
      ],
      [
        Buffer.from("id|general|agent_x|intel|0|1794432000000|deadbeef"),
        "1b702678d9ee26a2f097ce52759c54693fb913f91d8c7c67ecc366670ea1239" +
          "ce8045ffeb0ad9fb59a5f6c04a30065248af86846b7afe2dfddc57c22ab29eb04",
      ],
    ];
    for (const [message, expectedSig] of cases) {
      const signature = ed25519.sign(seed, message);
      assert.equal(signature.toString("hex"), expectedSig);
      assert.equal(ed25519.verify(publicKey, message, signature), true);
    }
  });

  it("matches RFC 8032 section 7.1 test 2 public key", () => {
    const seed = Buffer.from(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "hex",
    );
    assert.equal(
      ed25519.publicKeyFromSeed(seed).toString("hex"),
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    );
  });

  it("sign/verify round-trips and rejects tampering", () => {
    for (let i = 0; i < 3; i++) {
      const seed = ed25519.generateSeed();
      const publicKey = ed25519.publicKeyFromSeed(seed);
      const message = randomBytes(64);
      const signature = ed25519.sign(seed, message);
      assert.equal(ed25519.verify(publicKey, message, signature), true);
      assert.equal(ed25519.verify(publicKey, Buffer.concat([message, Buffer.from("x")]), signature), false);
      const tampered = Buffer.from(signature);
      tampered[0] ^= 1;
      assert.equal(ed25519.verify(publicKey, message, tampered), false);
    }
  });

  it("rejects malformed keys and signatures instead of throwing", () => {
    const seed = ed25519.generateSeed();
    const publicKey = ed25519.publicKeyFromSeed(seed);
    const signature = ed25519.sign(seed, Buffer.from("m"));
    assert.equal(ed25519.verify(Buffer.alloc(31), Buffer.from("m"), signature), false);
    assert.equal(ed25519.verify(publicKey, Buffer.from("m"), Buffer.alloc(63)), false);
    assert.equal(ed25519.verify(Buffer.alloc(32), Buffer.from("m"), signature), false);
  });

  it("round-trips PKCS#8 and rejects a bad prefix", () => {
    const seed = ed25519.generateSeed();
    const pkcs8 = ed25519.seedToPkcs8Hex(seed);
    assert.equal(pkcs8.length, 96);
    assert.deepEqual(ed25519.pkcs8HexToSeed(pkcs8), seed);
    assert.throws(() => ed25519.pkcs8HexToSeed("00".repeat(48)), /not an Ed25519 PKCS#8/);
    assert.throws(() => ed25519.pkcs8HexToSeed("zz"), /not an Ed25519 PKCS#8/);
  });

  it("rejects wrong-length seeds", () => {
    assert.throws(() => ed25519.publicKeyFromSeed(Buffer.alloc(31)), /32 bytes/);
    assert.throws(() => ed25519.sign(Buffer.alloc(33), Buffer.alloc(0)), /32 bytes/);
  });
});
