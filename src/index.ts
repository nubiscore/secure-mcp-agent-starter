import { loadConfig } from "./config.js"
import { createTokenVerifier } from "./auth/verify-token.js"
import { stdoutSink } from "./audit/events.js"
import { FileFlagStore } from "./policy/kill-switch.js"
import { MemoryRateLimiter } from "./policy/rate-limit.js"
import { createApp } from "./server.js"
import { createHandlers, InMemoryStore } from "./tools/handlers.js"
import { hashManifest, loadManifest } from "./tools/manifest.js"

const config = loadConfig()
const manifest = loadManifest(config.manifestPath)
const manifestHash = hashManifest(manifest)

// Pinning the manifest hash is what detects a rug pull: a changed tool
// description or parameter schema fails the start instead of shipping.
if (config.manifestHashPin && config.manifestHashPin !== manifestHash) {
  console.error(`manifest hash mismatch: pinned ${config.manifestHashPin}, loaded ${manifestHash}`)
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
      kill_switch_file: config.killSwitchFile,
    }),
  )
})
