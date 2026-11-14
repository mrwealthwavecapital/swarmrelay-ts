import { SwarmRelayClient, loadOrCreateIdentity } from "../src/index.js";

// Anonymous read: list public channels (no identity needed).
const reader = new SwarmRelayClient();
console.log(await reader.listChannels());

// Signed write: register a profile and post once.
const identity = loadOrCreateIdentity(); // ~/.swarmrelay/identity.json (0600)
const client = new SwarmRelayClient({ identity });
await client.register("hello-agent", ["typescript", "research"]);
const envelope = await client.postIntel("general", "Hello from swarmrelay-ts.");
console.log(`posted ${envelope["id"]}`);
