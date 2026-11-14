import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canonicalizeJson } from "../src/canonical.js";

describe("canonicalizeJson", () => {
  it("sorts keys and emits compact JSON", () => {
    assert.equal(canonicalizeJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
    assert.equal(
      canonicalizeJson({ z: { y: [3, 2, 1], x: null } }),
      '{"z":{"x":null,"y":[3,2,1]}}',
    );
  });

  it("formats numbers like JavaScript JSON.stringify", () => {
    assert.equal(canonicalizeJson({ n: 1.5 }), '{"n":1.5}');
    assert.equal(canonicalizeJson({ n: 1000000000000000 }), '{"n":1000000000000000}');
    assert.equal(canonicalizeJson({ n: 0.0000001 }), '{"n":1e-7}');
    assert.equal(canonicalizeJson({ n: 1e21 }), '{"n":1e+21}');
    assert.equal(canonicalizeJson({ n: -0 }), '{"n":0}');
    assert.equal(canonicalizeJson({ n: Number.NaN }), '{"n":null}');
    assert.equal(canonicalizeJson({ n: 1794432000000 }), '{"n":1794432000000}');
  });

  it("handles strings and unicode without escaping non-ASCII", () => {
    assert.equal(canonicalizeJson({ s: "héllo→" }), '{"s":"héllo→"}');
    assert.equal(canonicalizeJson({ s: 'a"b\\c\nd' }), '{"s":"a\\"b\\\\c\\nd"}');
  });

  it("is stable under parse round-trips", () => {
    const value = { b: [1, { d: 4, c: 3 }], a: "x" };
    const first = canonicalizeJson(value);
    assert.equal(canonicalizeJson(JSON.parse(first)), first);
  });

  it("drops undefined object values and nulls them in arrays", () => {
    assert.equal(canonicalizeJson({ a: undefined, b: 1 }), '{"b":1}');
    assert.equal(canonicalizeJson([undefined, 1]), "[null,1]");
  });

  it("rejects values with no JSON representation at the top level", () => {
    assert.throws(() => canonicalizeJson(undefined), TypeError);
    assert.throws(() => canonicalizeJson(() => 1), TypeError);
  });
});
