import { loadConfig } from "./config.js"
import { createTokenVerifier } from "./auth/verify-token.js"
import { stdoutSink } from "./audit/events.js"
import { FileFlagStore } from "./policy/kill-switch.js"
import { MemoryRateLimiter } from "./policy/rate-limit.js"
import { createApp } from "./server.js"
import { createHandlers, InMemoryStore } from "./tools/handlers.js"
import { assertManifestPinned, loadManifest } from "./tools/manifest.js"

const config = loadConfig()
const manifest = loadManifest(config.manifestPath)

// Startup guards. Each one turns a silent misconfiguration into a refusal to run.
let manifestHash: string
try {
  // Pinning the manifest hash is what detects a rug pull: a changed tool
  // description, parameter schema, or agent purpose fails the start.
  manifestHash = assertManifestPinned(manifest, config.manifestHashPin)
  if (manifest.resource !== config.canonicalUri) {
    throw new Error(`manifest.resource (${manifest.resource}) does not match MCP_CANONICAL_URI (${config.canonicalUri})`)
  }
  // The kill switch fails closed on every call if this file is unreadable,
  // which would look like an outage. Say so at startup instead.
  const flags = new FileFlagStore(config.killSwitchFile)
  flags.read()
} catch (err) {
  console.error(`startup refused: ${err instanceof Error ? err.message : String(err)}`)
  process.exit(1)
}

const app = createApp({
  manifest,
  manifestHash,
  handlers: createHandlers(new InMemoryStore()),
  flags: new FileFlagStore(config.killSwitchFile),
  rateLimiter: new MemoryRateLimiter(),
  budget: config.budget,
  audit: stdoutSink,
  canonicalUri: config.canonicalUri,
  issuer: config.issuer,
  verifier: createTokenVerifier({ issuer: config.issuer, canonicalUri: config.canonicalUri, jwks: config.jwksUrl }),
})

app.listen(config.port, () => {
  console.error(
    JSON.stringify({
      event: "server.started",
      port: config.port,
      canonical_uri: config.canonicalUri,
      issuer: config.issuer,
      manifest_hash: manifestHash,
      tools: manifest.tools.map((t) => t.name),
      agents: Object.keys(manifest.agents),
      kill_switch_file: config.killSwitchFile,
    }),
  )
})
