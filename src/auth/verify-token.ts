import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose"
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js"
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js"
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js"

/**
 * Identity carried by a verified access token.
 *
 *  - `subject`  : the delegating end user (who the agent acts FOR)
 *  - `actor`    : the agent workload (who the agent IS), from the RFC 8693 `act` claim
 *  - `clientId` : the OAuth client, used as the agent id for purpose binding
 *
 * The effective permission for any action is the intersection of user
 * authority and workload identity. Never the workload identity alone.
 */
export type VerifiedIdentity = {
  subject: string
  actor: string | undefined
  clientId: string
  scopes: string[]
}

export type VerifierOptions = {
  issuer: string
  /** Canonical URI of THIS server. The `aud` claim must match it exactly. */
  canonicalUri: string
  /** JWKS URL of the authorization server, or a pre-built key getter (tests). */
  jwks: string | JWTVerifyGetKey
}

type ActClaim = { sub?: unknown }

function readScopes(payload: JWTPayload): string[] {
  // RFC 8693 / RFC 9068 use a space-delimited `scope` string; some IdPs emit `scp` arrays.
  if (typeof payload.scope === "string") return payload.scope.split(" ").filter(Boolean)
  if (Array.isArray(payload.scp)) return payload.scp.filter((s): s is string => typeof s === "string")
  return []
}

function readActor(payload: JWTPayload): string | undefined {
  const act = payload.act as ActClaim | undefined
  return act && typeof act.sub === "string" ? act.sub : undefined
}

export function identityFromAuthInfo(auth: AuthInfo): VerifiedIdentity {
  const extra = (auth.extra ?? {}) as Partial<VerifiedIdentity>
  return {
    subject: extra.subject ?? "unknown",
    actor: extra.actor,
    clientId: auth.clientId,
    scopes: auth.scopes,
  }
}

/**
 * Builds the token verifier the MCP transport uses on every request.
 *
 * The audience check is the control. Without it, a token minted for any other
 * resource server in the estate is accepted here, and every other server
 * becomes a token source for this one (the confused deputy).
 */
export function createTokenVerifier(opts: VerifierOptions): OAuthTokenVerifier {
  const getKey: JWTVerifyGetKey = typeof opts.jwks === "string" ? createRemoteJWKSet(new URL(opts.jwks)) : opts.jwks

  return {
    async verifyAccessToken(raw: string): Promise<AuthInfo> {
      let payload: JWTPayload
      try {
        const result = await jwtVerify(raw, getKey, {
          issuer: opts.issuer,
          audience: opts.canonicalUri,
          algorithms: ["RS256", "ES256", "EdDSA"],
        })
        payload = result.payload
      } catch (err) {
        const message = err instanceof Error ? err.message : "token verification failed"
        throw new InvalidTokenError(message)
      }

      if (typeof payload.sub !== "string" || !payload.sub) {
        throw new InvalidTokenError("token has no subject")
      }
      const clientId = typeof payload.client_id === "string" ? payload.client_id : typeof payload.azp === "string" ? payload.azp : undefined
      if (!clientId) {
        throw new InvalidTokenError("token has no client_id")
      }

      const identity: VerifiedIdentity = {
        subject: payload.sub,
        actor: readActor(payload),
        clientId,
        scopes: readScopes(payload),
      }

      const info: AuthInfo = {
        token: raw,
        clientId,
        scopes: identity.scopes,
        resource: new URL(opts.canonicalUri),
        extra: identity,
      }
      if (typeof payload.exp === "number") info.expiresAt = payload.exp
      return info
    },
  }
}
