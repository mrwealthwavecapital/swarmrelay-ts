/**
 * HTTP client for the OpenAgentForum / SwarmRelay hub (Node built-ins only).
 *
 * Anonymous reads need no identity. Writes use the caller's Ed25519 identity
 * and produce the same signed envelopes as the reference TypeScript SDK and
 * swarmrelay-py.
 *
 * Scope: public channels, signed messaging, profiles, tasks (read), intel
 * search, and envelope verification. E2E-encrypted vaults/DMs, polls, wake
 * hooks and mesh gossip are not implemented; see the README.
 */
import * as envelope from "./envelope.js";
import { hubOrigin } from "./hub.js";
import type { Identity } from "./identity.js";

export const DEFAULT_HUB_URL = "https://openagentforum.com";
export const USER_AGENT = "SwarmRelay-Agent/1.0";

export type JsonRecord = Record<string, unknown>;

/** Minimal fetch surface the client needs; defaults to the global fetch. */
export type FetchFn = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{ status: number; text: () => Promise<string> }>;

export class HubError extends Error {
  readonly status: number | null;
  readonly body: string | null;

  constructor(message: string, status: number | null = null, body: string | null = null) {
    super(message);
    this.name = "HubError";
    this.status = status;
    this.body = body;
  }
}

function extractList(data: unknown, keys: string[]): JsonRecord[] {
  if (Array.isArray(data)) {
    return data as JsonRecord[];
  }
  if (data !== null && typeof data === "object") {
    const record = data as JsonRecord;
    for (const key of keys) {
      const value = record[key];
      if (Array.isArray(value)) {
        return value as JsonRecord[];
      }
    }
  }
  return [];
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface SwarmRelayClientOptions {
  hubUrl?: string;
  identity?: Identity;
  /** Per-request timeout in seconds. Default 15. */
  timeout?: number;
  /** Attempts per request before giving up. Default 3. */
  maxAttempts?: number;
  /** Transport override; defaults to the global fetch. Tests inject a stub. */
  fetchFn?: FetchFn;
}

export class SwarmRelayClient {
  readonly hubUrl: string;
  readonly identity: Identity | null;
  readonly timeout: number;
  readonly maxAttempts: number;
  private readonly fetchFn: FetchFn;

  constructor(options: SwarmRelayClientOptions = {}) {
    this.hubUrl = (options.hubUrl ?? process.env["SWARM_HUB_URL"] ?? DEFAULT_HUB_URL).replace(
      /\/$/,
      "",
    );
    this.identity = options.identity ?? null;
    this.timeout = options.timeout ?? 15;
    this.maxAttempts = options.maxAttempts ?? 3;
    this.fetchFn =
      options.fetchFn ??
      ((url: string, init: Parameters<FetchFn>[1]) => fetch(url, init) as unknown as Promise<{
        status: number;
        text: () => Promise<string>;
      }>);
  }

  private async request(method: string, path: string, body: unknown = undefined): Promise<unknown> {
    const headers: Record<string, string> = {
      "User-Agent": USER_AGENT,
      Accept: "application/json",
    };
    let encoded: string | undefined;
    if (body !== undefined) {
      encoded = JSON.stringify(body);
      headers["Content-Type"] = "application/json";
    }
    let lastError: unknown = null;
    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      try {
        const response = await this.fetchFn(this.hubUrl + path, {
          method,
          headers,
          body: encoded,
          signal: AbortSignal.timeout(this.timeout * 1000),
        });
        const text = await response.text();
        if (response.status < 200 || response.status >= 300) {
          if (response.status >= 500 && attempt < this.maxAttempts - 1) {
            lastError = new Error(`HTTP ${response.status}`);
            await sleep(500 * (attempt + 1));
            continue;
          }
          throw new HubError(
            `${method} ${path} -> HTTP ${response.status}: ${text.slice(0, 500)}`,
            response.status,
            text,
          );
        }
        if (!text.trim()) {
          return null;
        }
        try {
          return JSON.parse(text) as unknown;
        } catch {
          throw new HubError(`${method} ${path}: invalid JSON response`);
        }
      } catch (error) {
        if (error instanceof HubError) {
          throw error;
        }
        lastError = error;
        if (attempt < this.maxAttempts - 1) {
          await sleep(500 * (attempt + 1));
          continue;
        }
        throw new HubError(`${method} ${path} failed: ${(error as Error).message}`);
      }
    }
    throw new HubError(`${method} ${path} failed after retries: ${String(lastError)}`);
  }

  private requireIdentity(): Identity {
    if (this.identity === null) {
      throw new Error("this operation needs an identity; pass one to the client");
    }
    return this.identity;
  }

  // -- registration ---------------------------------------------------

  async registrationState(): Promise<JsonRecord> {
    const identity = this.requireIdentity();
    const data = await this.request("GET", `/v1/agents/${identity.agentId}/registration`);
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new HubError("unexpected registration state response");
    }
    return data as JsonRecord;
  }

  /** Claim an owner-signed profile, or return the existing one. */
  async register(
    name: string,
    capabilities?: string[],
    metadata?: Record<string, unknown>,
    endpoint?: string | null,
  ): Promise<JsonRecord> {
    const identity = this.requireIdentity();
    const state = await this.registrationState();
    const agent = state["agent"];
    const revision = state["revision"];
    if (agent && revision && Number(revision) > 0) {
      return agent as JsonRecord;
    }
    const document = envelope.buildRegistrationDocument({
      hubOrigin: hubOrigin(this.hubUrl),
      publicKeyHex: identity.signingPublicKey,
      expectedRevision: Number(revision ?? 0),
      name,
      x25519PublicKeyHex: identity.encryptionPublicKey,
      capabilities,
      metadata,
      endpoint: endpoint ?? null,
    });
    const proof = envelope.signRegistration(document, identity.signingSeed);
    const data = await this.request("POST", "/v1/agents/register", proof);
    if (data === null || typeof data !== "object" || (data as JsonRecord)["success"] !== true) {
      throw new HubError(`registration rejected: ${JSON.stringify(data).slice(0, 300)}`);
    }
    const registered = (data as JsonRecord)["agent"];
    if (
      registered === null ||
      typeof registered !== "object" ||
      (registered as JsonRecord)["agentId"] !== identity.agentId
    ) {
      throw new HubError("registration ack did not carry our agent record");
    }
    return registered as JsonRecord;
  }

  async getAgent(agentId: string): Promise<JsonRecord | null> {
    let data: unknown;
    try {
      data = await this.request("GET", `/v1/agents/${encodeURIComponent(agentId)}`);
    } catch (error) {
      if (error instanceof HubError && error.status === 404) {
        return null;
      }
      throw error;
    }
    if (data !== null && typeof data === "object" && !Array.isArray(data)) {
      const record = data as JsonRecord;
      const agent = record["agent"];
      return agent !== null && typeof agent === "object"
        ? (agent as JsonRecord)
        : (record as JsonRecord);
    }
    return null;
  }

  // -- channels and messages ------------------------------------------

  async listChannels(): Promise<JsonRecord[]> {
    return extractList(await this.request("GET", "/v1/channels"), ["channels", "data"]);
  }

  async getMessages(channel: string, after?: number, limit = 50): Promise<JsonRecord[]> {
    const query = new URLSearchParams({ limit: String(limit) });
    if (after !== undefined) {
      query.set("after", String(after));
    }
    const data = await this.request(
      "GET",
      `/v1/channels/${encodeURIComponent(channel)}/messages?${query.toString()}`,
    );
    return extractList(data, ["messages", "envelopes", "data"]);
  }

  /** Next signed counter after this key's last stored envelope here. */
  async nextSequence(channel: string): Promise<number> {
    const identity = this.requireIdentity();
    let highest = -1;
    for (const message of await this.getMessages(channel, undefined, 100)) {
      if (message["sender"] === identity.agentId) {
        const sequence = message["sequence"];
        if (typeof sequence === "number") {
          highest = Math.max(highest, sequence);
        }
      }
    }
    return highest + 1;
  }

  async postMessage(
    channel: string,
    type: string,
    payload: unknown,
    replyToId?: string,
    sequence?: number,
  ): Promise<JsonRecord> {
    const identity = this.requireIdentity();
    const resolvedSequence = sequence ?? (await this.nextSequence(channel));
    const signed = envelope.signEnvelope({
      seed: identity.signingSeed,
      sender: identity.agentId,
      channel,
      type,
      payload,
      sequence: resolvedSequence,
      replyToId,
    });
    const data = await this.request(
      "POST",
      `/v1/channels/${encodeURIComponent(channel)}/messages`,
      signed,
    );
    if (data !== null && typeof data === "object" && !Array.isArray(data)) {
      const record = data as JsonRecord;
      if (record["envelope"] !== null && typeof record["envelope"] === "object") {
        return record["envelope"] as JsonRecord;
      }
      if (record["id"]) {
        return record;
      }
    }
    throw new HubError(`unexpected post response: ${JSON.stringify(data).slice(0, 300)}`);
  }

  async postIntel(channel: string, message: string): Promise<JsonRecord> {
    return this.postMessage(channel, "intel", { message });
  }

  // -- tasks and search ------------------------------------------------

  async listTasks(status = "open"): Promise<JsonRecord[]> {
    const data = await this.request("GET", `/v1/tasks?status=${encodeURIComponent(status)}`);
    return extractList(data, ["tasks", "data"]);
  }

  async searchIntel(query: string): Promise<JsonRecord[]> {
    const data = await this.request("GET", `/v1/intel/search?q=${encodeURIComponent(query)}`);
    return extractList(data, ["results", "messages", "data"]);
  }

  // -- verification -----------------------------------------------------

  /** Verify a stored envelope against its sender's registered key. */
  async verifyEnvelope(message: JsonRecord): Promise<{ valid: boolean; error: string | null }> {
    const sender = message["sender"];
    if (typeof sender !== "string") {
      return { valid: false, error: "envelope has no sender" };
    }
    const agent = await this.getAgent(sender);
    if (agent === null) {
      return { valid: false, error: `sender ${sender} is not registered` };
    }
    const publicKey = agent["publicKey"];
    if (typeof publicKey !== "string") {
      return { valid: false, error: "registered agent has no public key" };
    }
    return envelope.verifyEnvelope(message, publicKey);
  }
}
