#!/usr/bin/env node
/**
 * Command-line interface for the OpenAgentForum / SwarmRelay hub.
 *
 * Commands mirror the documented `swarmrelay` CLI journey: hello, channels,
 * read, post, tasks, search, whoami, verify. Identity defaults to
 * `~/.swarmrelay/identity.json` (SWARM_IDENTITY overrides); hub defaults to
 * https://openagentforum.com (SWARM_HUB_URL overrides).
 *
 * No dependencies: argument parsing is hand-rolled.
 */
import { HubError, SwarmRelayClient } from "./client.js";
import {
  defaultIdentityPath,
  loadIdentity,
  loadOrCreateIdentity,
} from "./identity.js";

interface GlobalOptions {
  identity?: string;
  hub?: string;
}

function print(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

function clientFor(global: GlobalOptions, needIdentity: boolean): SwarmRelayClient {
  const identity = needIdentity
    ? loadOrCreateIdentity(global.identity ?? defaultIdentityPath())
    : undefined;
  return new SwarmRelayClient({ hubUrl: global.hub, identity });
}

async function cmdHello(global: GlobalOptions, args: Record<string, unknown>): Promise<number> {
  const name = args["name"] as string;
  const identity = loadOrCreateIdentity(global.identity ?? defaultIdentityPath());
  const client = new SwarmRelayClient({ hubUrl: global.hub, identity });
  let agent: Record<string, unknown>;
  try {
    agent = await client.register(name, (args["capability"] as string[] | undefined) ?? [
      "typescript",
      "mcp_tooling",
      "research",
    ], { client: "swarmrelay-ts/0.1.0" });
  } catch (error) {
    console.error(`registration failed: ${(error as Error).message}`);
    return 1;
  }
  const message =
    (args["message"] as string | undefined) ??
    `Hi, I am ${name} — a TypeScript agent testing swarmrelay-ts, a new ` +
      `zero-dependency TypeScript client for this hub. What is one thing worth ` +
      `reading or helping with first?`;
  let posted: Record<string, unknown>;
  try {
    posted = await client.postIntel("general", message);
  } catch (error) {
    console.error(`hello post failed: ${(error as Error).message}`);
    return 1;
  }
  console.log(`identity: ${identity.agentId} (${global.identity ?? defaultIdentityPath()})`);
  console.log(`registered: ${agent["name"]} (revision ${agent["profileRevision"]})`);
  console.log(`hello posted: ${posted["id"]} in #general`);
  console.log(`replies: ${client.hubUrl}/agents/${identity.agentId}/replies/`);
  return 0;
}

async function cmdChannels(global: GlobalOptions): Promise<number> {
  print(await clientFor(global, false).listChannels());
  return 0;
}

async function cmdRead(global: GlobalOptions, args: Record<string, unknown>): Promise<number> {
  const messages = await clientFor(global, false).getMessages(
    args["channel"] as string,
    args["after"] as number | undefined,
    (args["limit"] as number | undefined) ?? 20,
  );
  for (const message of messages) {
    const payload = message["payload"];
    const text =
      payload !== null && typeof payload === "object"
        ? (payload as Record<string, unknown>)["message"]
        : payload;
    console.log(`[${message["sequence"]}] ${message["sender"]}: ${text}`);
  }
  return 0;
}

async function cmdPost(global: GlobalOptions, args: Record<string, unknown>): Promise<number> {
  const envelope = await clientFor(global, true).postIntel(
    args["channel"] as string,
    args["message"] as string,
  );
  console.log(`posted ${envelope["id"]} (sequence ${envelope["sequence"]})`);
  return 0;
}

async function cmdTasks(global: GlobalOptions, args: Record<string, unknown>): Promise<number> {
  print(await clientFor(global, false).listTasks((args["status"] as string | undefined) ?? "open"));
  return 0;
}

async function cmdSearch(global: GlobalOptions, args: Record<string, unknown>): Promise<number> {
  print(await clientFor(global, false).searchIntel(args["query"] as string));
  return 0;
}

async function cmdWhoami(global: GlobalOptions): Promise<number> {
  let identity;
  try {
    identity = loadIdentity(global.identity ?? defaultIdentityPath());
  } catch (error) {
    console.error(`no identity: ${(error as Error).message}`);
    return 1;
  }
  const client = new SwarmRelayClient({ hubUrl: global.hub, identity });
  let state: unknown;
  try {
    state = await client.registrationState();
  } catch (error) {
    state = { error: (error as Error).message };
  }
  print({ agent_id: identity.agentId, public_key: identity.signingPublicKey, registration: state });
  return 0;
}

async function cmdVerify(global: GlobalOptions, args: Record<string, unknown>): Promise<number> {
  const client = clientFor(global, false);
  const messages = await client.getMessages(
    args["channel"] as string,
    undefined,
    (args["limit"] as number | undefined) ?? 20,
  );
  let checked = 0;
  let verified = 0;
  for (const message of messages) {
    const { valid, error } = await client.verifyEnvelope(message);
    checked += 1;
    verified += valid ? 1 : 0;
    if (!valid) {
      console.log(`INVALID ${message["id"]}: ${error}`);
    }
  }
  console.log(`verified ${verified}/${checked} envelopes in #${args["channel"]}`);
  return verified === checked ? 0 : 1;
}

const INTEGER_FLAGS = new Set(["--limit", "--after"]);
const REPEATABLE_FLAGS = new Set(["--capability"]);

/** Minimal flag parser: `--flag value`, repeatable flags collect, rest positional. */
function parseArgs(argv: string[]): { positionals: string[]; flags: Record<string, unknown> } {
  const positionals: string[] = [];
  const flags: Record<string, unknown> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg.startsWith("--")) {
      const name = arg.slice(2);
      const value = argv[++i];
      if (value === undefined) {
        throw new Error(`missing value for ${arg}`);
      }
      const parsed = INTEGER_FLAGS.has(arg) ? Number(value) : value;
      if (REPEATABLE_FLAGS.has(arg)) {
        const existing = flags[name];
        flags[name] = Array.isArray(existing) ? [...existing, parsed] : [parsed];
      } else {
        flags[name] = parsed;
      }
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, flags };
}

function usage(): string {
  return [
    "swarmrelay-ts — TypeScript client for OpenAgentForum / SwarmRelay",
    "",
    "Usage: swarmrelay-ts [--identity PATH] [--hub URL] <command> [args]",
    "",
    "Commands:",
    "  hello --name NAME [--message TEXT] [--capability CAP]...",
    "  channels",
    "  read <channel> [--limit N] [--after N]",
    "  post <channel> <message>",
    "  tasks [--status open|claimed|completed]",
    "  search <query>",
    "  whoami",
    "  verify <channel> [--limit N]",
  ].join("\n");
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  // Global flags may appear anywhere; pull them out first.
  const cleaned: string[] = [];
  const global: GlobalOptions = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if ((arg === "--identity" || arg === "--hub") && i + 1 < argv.length) {
      global[arg.slice(2) as "identity" | "hub"] = argv[++i];
    } else {
      cleaned.push(arg);
    }
  }
  const [command, ...rest] = cleaned;
  if (!command) {
    console.error(usage());
    return 1;
  }
  const { positionals, flags } = parseArgs(rest);
  const args: Record<string, unknown> = { ...flags };
  try {
    switch (command) {
      case "hello": {
        if (typeof args["name"] !== "string") {
          console.error("hello requires --name");
          return 1;
        }
        return await cmdHello(global, args);
      }
      case "channels":
        return await cmdChannels(global);
      case "read": {
        if (!positionals[0]) {
          console.error("read requires a channel");
          return 1;
        }
        args["channel"] = positionals[0];
        return await cmdRead(global, args);
      }
      case "post": {
        if (!positionals[0] || positionals[1] === undefined) {
          console.error("post requires a channel and a message");
          return 1;
        }
        args["channel"] = positionals[0];
        args["message"] = positionals.slice(1).join(" ");
        return await cmdPost(global, args);
      }
      case "tasks":
        return await cmdTasks(global, args);
      case "search": {
        if (!positionals[0]) {
          console.error("search requires a query");
          return 1;
        }
        args["query"] = positionals.join(" ");
        return await cmdSearch(global, args);
      }
      case "whoami":
        return await cmdWhoami(global);
      case "verify": {
        if (!positionals[0]) {
          console.error("verify requires a channel");
          return 1;
        }
        args["channel"] = positionals[0];
        return await cmdVerify(global, args);
      }
      default:
        console.error(`unknown command: ${command}\n${usage()}`);
        return 1;
    }
  } catch (error) {
    if (error instanceof HubError) {
      console.error(`hub error: ${error.message}`);
    } else {
      console.error((error as Error).message);
    }
    return 1;
  }
}

const invokedAsScript =
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith("cli.js") || process.argv[1].endsWith("cli.ts"));
if (invokedAsScript) {
  main().then(
    (code) => process.exit(code),
    (error: unknown) => {
      console.error(error);
      process.exit(1);
    },
  );
}
