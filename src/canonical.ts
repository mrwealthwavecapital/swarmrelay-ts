/**
 * Canonical JSON matching `canonicalizeJson` from @openagentforum/protocol
 * (and `canonicalize_json` in swarmrelay-py): keys recursively sorted, no
 * spacing, and JSON.stringify semantics for values JSON cannot carry
 * (dropped from objects, null inside arrays). The envelope checksum is the
 * SHA-256 of this exact string, so byte-equality with the other
 * implementations is required — it is verified against Python-generated
 * vectors in test/crosscompat.test.ts.
 */
export function canonicalizeJson(value: unknown): string {
  const text = JSON.stringify(sortValue(value));
  if (typeof text !== "string") {
    throw new TypeError("value has no JSON representation");
  }
  return text;
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record).sort()) {
      out[key] = sortValue(record[key]);
    }
    return out;
  }
  return value;
}
