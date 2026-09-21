import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from "jose"

export const TEST_ISSUER = "https://auth.test"
export const TEST_RESOURCE = "https://mcp.test"

export type TestIssuer = {
  issuer: string
  getKey: JWTVerifyGetKey
  mint(claims: { sub: string; client_id: string; scope: string; aud?: string | string[]; act?: { sub: string }; exp?: string; iss?: string }): Promise<string>
}

export async function createTestIssuer(): Promise<TestIssuer> {
  const { publicKey, privateKey } = await generateKeyPair("RS256")
  const jwk = await exportJWK(publicKey)
  const kid = "test"
  const getKey = createLocalJWKSet({ keys: [{ ...jwk, kid, alg: "RS256" }] })
  return {
    issuer: TEST_ISSUER,
    getKey,
    async mint(claims) {
      return new SignJWT({ scope: claims.scope, client_id: claims.client_id, ...(claims.act ? { act: claims.act } : {}) })
        .setProtectedHeader({ alg: "RS256", kid })
        .setIssuer(claims.iss ?? TEST_ISSUER)
        .setSubject(claims.sub)
        .setAudience(claims.aud ?? TEST_RESOURCE)
        .setIssuedAt()
        .setExpirationTime(claims.exp ?? "5m")
        .sign(privateKey)
    },
  }
}
