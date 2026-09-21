import { describe, expect, it } from "vitest"
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js"
import { createTokenVerifier, identityFromAuthInfo } from "../src/auth/verify-token.js"
import { createTestIssuer, TEST_ISSUER, TEST_RESOURCE } from "./helpers.js"

describe("token verifier", async () => {
  const issuer = await createTestIssuer()
  const verifier = createTokenVerifier({ issuer: TEST_ISSUER, canonicalUri: TEST_RESOURCE, jwks: issuer.getKey })

  it("accepts a token minted for this server and exposes the delegation chain", async () => {
    const token = await issuer.mint({ sub: "user_1", client_id: "agent-a", scope: "tickets:read kb:search", act: { sub: "spiffe://x/agent-a" } })
    const info = await verifier.verifyAccessToken(token)
    const id = identityFromAuthInfo(info)
    expect(id).toEqual({ subject: "user_1", actor: "spiffe://x/agent-a", clientId: "agent-a", scopes: ["tickets:read", "kb:search"] })
    expect(info.resource?.href).toBe(`${TEST_RESOURCE}/`)
    expect(typeof info.expiresAt).toBe("number")
  })

  it("rejects a token minted for a different resource server (audience check)", async () => {
    const token = await issuer.mint({ sub: "user_1", client_id: "agent-a", scope: "tickets:read", aud: "https://finance.test" })
    await expect(verifier.verifyAccessToken(token)).rejects.toBeInstanceOf(InvalidTokenError)
  })

  it("rejects a token valid for several resource servers, even if this one is among them", async () => {
    const token = await issuer.mint({ sub: "user_1", client_id: "agent-a", scope: "tickets:read", aud: [TEST_RESOURCE, "https://finance.test"] })
    await expect(verifier.verifyAccessToken(token)).rejects.toBeInstanceOf(InvalidTokenError)
  })

  it("refuses to derive an identity from auth info without a subject", async () => {
    expect(() => identityFromAuthInfo({ token: "x", clientId: "agent-a", scopes: [] })).toThrow(/no subject/)
  })

  it("rejects a token from a different issuer", async () => {
    const token = await issuer.mint({ sub: "user_1", client_id: "agent-a", scope: "tickets:read", iss: "https://evil.test" })
    await expect(verifier.verifyAccessToken(token)).rejects.toBeInstanceOf(InvalidTokenError)
  })

  it("rejects an expired token", async () => {
    const token = await issuer.mint({ sub: "user_1", client_id: "agent-a", scope: "tickets:read", exp: "-1m" })
    await expect(verifier.verifyAccessToken(token)).rejects.toBeInstanceOf(InvalidTokenError)
  })

  it("rejects garbage", async () => {
    await expect(verifier.verifyAccessToken("not.a.jwt")).rejects.toBeInstanceOf(InvalidTokenError)
  })
})
