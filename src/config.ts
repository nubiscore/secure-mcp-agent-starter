/**
 * All configuration comes from the environment. Nothing here is a secret:
 * the server holds no long-lived credentials of its own. It verifies tokens
 * issued by the authorization server using that server's public JWKS.
 */
export type Config = {
  port: number
  canonicalUri: string
  issuer: string
  jwksUrl: string
  manifestPath: string
  manifestHashPin: string | undefined
  killSwitchFile: string
  budget: {
    maxIterations: number
    maxToolCalls: number
    maxTokens: number
    maxMutations: number
  }
}

function int(name: string, fallback: number): number {
  const raw = process.env[name]
  if (raw === undefined || raw === "") return fallback
  const n = Number.parseInt(raw, 10)
  if (!Number.isFinite(n)) throw new Error(`${name} must be an integer, got "${raw}"`)
  return n
}

function str(name: string, fallback: string): string {
  const raw = process.env[name]
  return raw === undefined || raw === "" ? fallback : raw
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const issuer = str("OAUTH_ISSUER", "http://localhost:3000").replace(/\/$/, "")
  const canonicalUri = str("MCP_CANONICAL_URI", "http://localhost:3001").replace(/\/$/, "")
  return {
    port: int("PORT", 3001),
    canonicalUri,
    issuer,
    jwksUrl: str("OAUTH_JWKS_URL", `${issuer}/.well-known/jwks.json`),
    manifestPath: str("TOOL_MANIFEST", "./tools/manifest.yaml"),
    manifestHashPin: env.MANIFEST_HASH_PIN || undefined,
    killSwitchFile: str("KILL_SWITCH_FILE", "./dev/kill-switch.json"),
    budget: {
      maxIterations: int("BUDGET_MAX_ITERATIONS", 8),
      maxToolCalls: int("BUDGET_MAX_TOOL_CALLS", 20),
      maxTokens: int("BUDGET_MAX_TOKENS", 120_000),
      maxMutations: int("BUDGET_MAX_MUTATIONS", 3),
    },
  }
}
