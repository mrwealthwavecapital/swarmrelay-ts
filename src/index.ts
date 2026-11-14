/**
 * swarmrelay-ts: zero-dependency TypeScript client + MCP server for OpenAgentForum.
 *
 * Speaks the SwarmRelay 1.0 protocol (Ed25519-signed envelopes, v2 profile
 * registration) against any compatible hub, with identity files
 * byte-compatible with the `swarmrelay` CLI, its MCP server, and
 * swarmrelay-py.
 */
export { canonicalizeJson } from "./canonical.js";
export {
  HubError,
  SwarmRelayClient,
  DEFAULT_HUB_URL,
  USER_AGENT,
  type FetchFn,
  type JsonRecord,
  type SwarmRelayClientOptions,
} from "./client.js";
export {
  generateSeed,
  publicKeyFromSeed,
  sign,
  verify,
  seedToPkcs8Hex,
  pkcs8HexToSeed,
} from "./ed25519.js";
export {
  REGISTRATION_DOMAIN,
  REGISTRATION_MAX_AGE_MS,
  buildRegistrationDocument,
  deriveAgentId,
  envelopeSignString,
  payloadChecksum,
  registrationDigest,
  sha256Hex,
  signEnvelope,
  signRegistration,
  verifyEnvelope,
  type Envelope,
  type RegistrationDocument,
  type RegistrationProfile,
  type SignedRegistration,
} from "./envelope.js";
export { hubOrigin } from "./hub.js";
export {
  DEFAULT_IDENTITY_PATH,
  defaultIdentityPath,
  generateIdentity,
  identityFromFileDict,
  identityToFileDict,
  loadIdentity,
  loadOrCreateIdentity,
  saveIdentity,
  type Identity,
  type IdentityFileDict,
} from "./identity.js";
export {
  generatePrivate,
  pkcs8HexToPrivate,
  privateToPkcs8Hex,
  publicKey as x25519PublicKey,
  scalarmult,
} from "./x25519.js";

export const VERSION = "0.1.0";
