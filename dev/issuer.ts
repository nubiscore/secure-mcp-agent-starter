/**
 * DEVELOPMENT-ONLY token issuer.
 *
 * It exists so the starter runs end-to-end on a laptop with no IdP. It mints
 * signed JWTs on request with no authentication, which is exactly what a real
 * authorization server must never do. In production point OAUTH_ISSUER and
 * OAUTH_JWKS_URL at Keycloak, Entra ID, Okta, Auth0, or your own AS, and delete
 * this file from your deployment.
 *
 * It does enforce ONE real rule: the RFC 8707 `resource` parameter is required,
 * and becomes the token's `aud`. Omit it and you get a 400, not a broad token.
 */
import express from "express"
import { exportJWK, generateKeyPair, SignJWT } from "jose"

const PORT = Number.parseInt(process.env.ISSUER_PORT ?? "3000", 10)
const HOST = process.env.HOST ?? "0.0.0.0"
const ISSUER = (process.env.OAUTH_ISSUER ?? `http://localhost:${PORT}`).replace(/\/$/, "")

const { publicKey, privateKey } = await generateKeyPair("RS256")
const jwk = await exportJWK(publicKey)
const kid = "dev-" + Date.now().toString(36)
const jwks = { keys: [{ ...jwk, kid, alg: "RS256", use: "sig" }] }

const app = express()
app.use(express.json())

app.get("/.well-known/jwks.json", (_req, res) => {
  res.json(jwks)
})

app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json({
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    token_endpoint: `${ISSUER}/dev/token`,
    authorization_endpoint: `${ISSUER}/dev/authorize-not-implemented`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["tickets:read", "tickets:comment", "kb:search", "billing:refund", "agent:operate"],
  })
})

type MintRequest = {
  sub?: string
  client_id?: string
  scope?: string
  resource?: string
  act?: { sub: string }
  ttl_seconds?: number
}

app.post("/dev/token", async (req, res) => {
  const body = req.body as MintRequest
  if (!body.resource) {
    // RFC 8707: the resource indicator is mandatory. This is the audience restriction.
    res.status(400).json({ error: "invalid_target", error_description: "resource parameter is required" })
    return
  }
  if (!body.sub || !body.client_id) {
    res.status(400).json({ error: "invalid_request", error_description: "sub and client_id are required" })
    return
  }
  const ttl = body.ttl_seconds ?? 900
  const token = await new SignJWT({
    scope: body.scope ?? "",
    client_id: body.client_id,
    ...(body.act ? { act: body.act } : {}),
  })
    .setProtectedHeader({ alg: "RS256", kid, typ: "at+jwt" })
    .setIssuer(ISSUER)
    .setSubject(body.sub)
    .setAudience(body.resource)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .setJti(crypto.randomUUID())
    .sign(privateKey)
  res.json({ access_token: token, token_type: "Bearer", expires_in: ttl, scope: body.scope ?? "" })
})

app.listen(PORT, HOST, () => {
  console.error(`[dev-issuer] DEVELOPMENT ONLY. Listening on ${ISSUER}  kid=${kid}`)
})
