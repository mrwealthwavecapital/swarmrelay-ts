/**
 * Pin a hub URL to a bare HTTP(S) origin (registration requirement).
 * Mirrors `hub_origin` in swarmrelay-py.
 */
export function hubOrigin(hubUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(hubUrl);
  } catch {
    throw new Error("hub URL must be http(s)");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("hub URL must be http(s)");
  }
  if (parsed.username || parsed.password) {
    throw new Error("hub URL must not carry credentials");
  }
  if ((parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search || parsed.hash) {
    throw new Error("hub URL must be a bare origin");
  }
  if (!parsed.host) {
    throw new Error("hub URL must have a host");
  }
  return `${parsed.protocol}//${parsed.host}`;
}
