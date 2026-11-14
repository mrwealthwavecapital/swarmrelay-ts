import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { HubError, SwarmRelayClient, type FetchFn } from "../src/client.js";
import * as ed25519 from "../src/ed25519.js";
import * as env from "../src/envelope.js";
import { hubOrigin } from "../src/hub.js";
import { generateIdentity } from "../src/identity.js";

interface RecordedRequest {
  url: string;
  method: string;
  body: string | undefined;
}

function stubFetch(
  handler: (request: RecordedRequest) => { status: number; body: unknown },
): { fetchFn: FetchFn; requests: RecordedRequest[] } {
  const requests: RecordedRequest[] = [];
  const fetchFn: FetchFn = async (url, init) => {
    const recorded = { url, method: init.method, body: init.body };
    requests.push(recorded);
    const { status, body } = handler(recorded);
    return { status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) };
  };
  return { fetchFn, requests };
}

describe("hubOrigin", () => {
  it("accepts bare origins", () => {
    assert.equal(hubOrigin("https://openagentforum.com"), "https://openagentforum.com");
    assert.equal(hubOrigin("http://localhost:3000/"), "http://localhost:3000");
  });

  it("rejects paths, queries, fragments, credentials and bad schemes", () => {
    assert.throws(() => hubOrigin("https://openagentforum.com/v1"), /bare origin/);
    assert.throws(() => hubOrigin("https://openagentforum.com/?x=1"), /bare origin/);
    assert.throws(() => hubOrigin("https://openagentforum.com/#f"), /bare origin/);
    assert.throws(() => hubOrigin("https://user@openagentforum.com"), /credentials/);
    assert.throws(() => hubOrigin("ftp://openagentforum.com"), /http\(s\)/);
  });
});

describe("SwarmRelayClient (offline, stubbed transport)", () => {
  it("registers with a verifiable v2 proof when unregistered", async () => {
    const identity = generateIdentity();
    const { fetchFn, requests } = stubFetch((request) => {
      if (request.url.endsWith("/registration")) {
        return { status: 200, body: { agent: null, revision: 0 } };
      }
      if (request.url.endsWith("/v1/agents/register")) {
        return {
          status: 200,
          body: { success: true, agent: { agentId: identity.agentId, name: "ts-agent" } },
        };
      }
      return { status: 404, body: {} };
    });
    const client = new SwarmRelayClient({ identity, fetchFn });
    const agent = await client.register("ts-agent", ["typescript"]);
    assert.equal(agent["agentId"], identity.agentId);

    const post = requests.find((r) => r.url.endsWith("/v1/agents/register"));
    assert.ok(post?.body);
    const proof = JSON.parse(post.body) as Record<string, unknown>;
    assert.equal(proof["proofVersion"], 2);
    assert.equal(proof["expectedRevision"], 0);
    const { signature, ...document } = proof;
    const { canonicalizeJson } = await import("../src/canonical.js");
    const canonicalMessage = Buffer.from(
      env.REGISTRATION_DOMAIN + canonicalizeJson(document),
      "utf-8",
    );
    assert.equal(
      ed25519.verify(
        Buffer.from(identity.signingPublicKey, "hex"),
        canonicalMessage,
        Buffer.from(String(signature), "hex"),
      ),
      true,
    );
  });

  it("returns the existing agent without posting when already registered", async () => {
    const identity = generateIdentity();
    const { fetchFn, requests } = stubFetch((request) => {
      if (request.url.endsWith("/registration")) {
        return {
          status: 200,
          body: { agent: { agentId: identity.agentId, name: "old" }, revision: 2 },
        };
      }
      return { status: 404, body: {} };
    });
    const client = new SwarmRelayClient({ identity, fetchFn });
    const agent = await client.register("new-name");
    assert.equal(agent["name"], "old");
    assert.equal(requests.filter((r) => r.method === "POST").length, 0);
  });

  it("posts a signed envelope with the next sequence number", async () => {
    const identity = generateIdentity();
    const { fetchFn, requests } = stubFetch((request) => {
      if (request.method === "GET" && request.url.includes("/messages")) {
        return {
          status: 200,
          body: {
            messages: [
              { sender: identity.agentId, sequence: 4 },
              { sender: "agent_other", sequence: 9 },
              { sender: identity.agentId, sequence: 2 },
            ],
          },
        };
      }
      if (request.method === "POST") {
        return { status: 200, body: { envelope: { id: "env-1", sequence: 5 } } };
      }
      return { status: 404, body: {} };
    });
    const client = new SwarmRelayClient({ identity, fetchFn });
    const posted = await client.postIntel("general", "hello");
    assert.equal(posted["sequence"], 5);

    const post = requests.find((r) => r.method === "POST");
    assert.ok(post?.body);
    const sent = JSON.parse(post.body) as Record<string, unknown>;
    assert.equal(sent["sequence"], 5);
    assert.equal(sent["sender"], identity.agentId);
    const { valid, error } = env.verifyEnvelope(sent, identity.signingPublicKey);
    assert.equal(valid, true, error ?? "verification failed");
  });

  it("lists channels, tasks and search results from wrapped payloads", async () => {
    const { fetchFn } = stubFetch((request) => {
      if (request.url.endsWith("/v1/channels")) return { status: 200, body: { channels: [{ name: "general" }] } };
      if (request.url.includes("/v1/tasks")) return { status: 200, body: { tasks: [{ id: "t1" }] } };
      if (request.url.includes("/v1/intel/search")) return { status: 200, body: { results: [{ id: "m1" }] } };
      return { status: 404, body: {} };
    });
    const client = new SwarmRelayClient({ fetchFn });
    assert.deepEqual(await client.listChannels(), [{ name: "general" }]);
    assert.deepEqual(await client.listTasks(), [{ id: "t1" }]);
    assert.deepEqual(await client.searchIntel("mcp"), [{ id: "m1" }]);
  });

  it("returns null for a missing agent and the agent record otherwise", async () => {
    const { fetchFn } = stubFetch((request) => {
      if (request.url.endsWith("/v1/agents/agent_nope")) return { status: 404, body: { error: "nope" } };
      return { status: 200, body: { agent: { agentId: "agent_yes", publicKey: "ab".repeat(32) } } };
    });
    const client = new SwarmRelayClient({ fetchFn });
    assert.equal(await client.getAgent("agent_nope"), null);
    assert.equal((await client.getAgent("agent_yes"))?.["agentId"], "agent_yes");
  });

  it("verifies an envelope against the sender's registered key", async () => {
    const identity = generateIdentity();
    const signed = env.signEnvelope({
      seed: identity.signingSeed,
      sender: identity.agentId,
      channel: "general",
      type: "intel",
      payload: { message: "hi" },
    });
    const { fetchFn } = stubFetch(() => ({
      status: 200,
      body: { agent: { agentId: identity.agentId, publicKey: identity.signingPublicKey } },
    }));
    const client = new SwarmRelayClient({ fetchFn });
    const { valid } = await client.verifyEnvelope(signed as unknown as Record<string, unknown>);
    assert.equal(valid, true);
  });

  it("raises HubError with status on HTTP errors and retries 5xx", async () => {
    let attempts = 0;
    const { fetchFn } = stubFetch(() => {
      attempts += 1;
      if (attempts < 3) return { status: 500, body: "boom" };
      return { status: 200, body: { channels: [] } };
    });
    const client = new SwarmRelayClient({ fetchFn, maxAttempts: 3 });
    assert.deepEqual(await client.listChannels(), []);
    assert.equal(attempts, 3);

    const failing = stubFetch(() => ({ status: 403, body: "forbidden" }));
    const bad = new SwarmRelayClient({ fetchFn: failing.fetchFn, maxAttempts: 2 });
    await assert.rejects(() => bad.listChannels(), (error: unknown) => {
      assert.ok(error instanceof HubError);
      assert.equal(error.status, 403);
      return true;
    });
    assert.equal(failing.requests.length, 1);
  });

  it("requires an identity for writes", async () => {
    const client = new SwarmRelayClient({});
    await assert.rejects(() => client.postIntel("general", "x"), /needs an identity/);
    await assert.rejects(() => client.register("x"), /needs an identity/);
  });
});
