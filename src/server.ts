import { randomUUID } from "node:crypto"
import express, { type Request, type Response } from "express"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js"
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js"
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js"
import { identityFromAuthInfo, type VerifiedIdentity } from "./auth/verify-token.js"
import { SessionState, SessionStore } from "./policy/session.js"
import { ApprovalRequestSchema, registerManifestTools, sessionMatchesIdentity, validateApprovalArguments, type GatewayDeps } from "./tools/registry.js"

export const OPERATOR_SCOPE = "agent:operate"

export type AppDeps = Omit<GatewayDeps, "sessions"> & {
  verifier: OAuthTokenVerifier
  issuer: string
  sessions?: SessionStore
  serverName?: string
  serverVersion?: string
  /** Sessions idle longer than this are closed. Default 30 minutes. */
  sessionIdleMs?: number
  /** Concurrent sessions one subject may hold. Default 5. */
  maxSessionsPerSubject?: number
  /** How often to sweep idle sessions. Default 60 seconds. 0 disables the timer (tests). */
  sweepIntervalMs?: number
}

/**
 * Builds the Express app. Routes:
 *
 *   GET  /.well-known/oauth-protected-resource   RFC 9728 metadata (unauthenticated, by design)
 *   POST /mcp                                     MCP Streamable HTTP (bearer token required)
 *   GET  /mcp, DELETE /mcp                        SSE stream / session close (bearer token, session-bound)
 *   POST /admin/approvals                         Human-in-the-loop approval (operator scope, separate identity)
 *   GET  /healthz
 */
export function createApp(deps: AppDeps) {
  const sessions = deps.sessions ?? new SessionStore()
  const transports = new Map<string, StreamableHTTPServerTransport>()
  const sessionIdleMs = deps.sessionIdleMs ?? 30 * 60 * 1000
  const maxSessionsPerSubject = deps.maxSessionsPerSubject ?? 5
  const app = express()
  app.disable("x-powered-by")
  app.use(express.json({ limit: "256kb" }))

  const resourceMetadataUrl = `${deps.canonicalUri}/.well-known/oauth-protected-resource`

  const sessionEvent = (
    event: "agent.session.opened" | "agent.session.closed" | "agent.session.expired" | "agent.session.refused",
    sessionId: string | null,
    identity: VerifiedIdentity,
    version: string,
    reason: string | null,
  ) =>
    deps.audit({
      event,
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      agent: { id: identity.clientId, version },
      on_behalf_of: identity.subject,
      reason,
    })

  const closeSession = (id: string) => {
    const transport = transports.get(id)
    transports.delete(id)
    sessions.delete(id)
    if (transport) void transport.close().catch(() => undefined)
  }

  // Idle sessions are swept so a valid token cannot grow memory without bound.
  const sweepIntervalMs = deps.sweepIntervalMs ?? 60_000
  if (sweepIntervalMs > 0) {
    const timer = setInterval(() => {
      for (const id of sessions.expireIdle(sessionIdleMs)) {
        const transport = transports.get(id)
        transports.delete(id)
        if (transport) void transport.close().catch(() => undefined)
      }
    }, sweepIntervalMs)
    timer.unref()
  }

  // 1. Protected resource metadata. This is how a client discovers which
  //    authorization server to use and what this server's canonical identifier is.
  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({
      resource: deps.canonicalUri,
      authorization_servers: [deps.issuer],
      scopes_supported: [...new Set(deps.manifest.tools.map((t) => t.required_scope))],
      bearer_methods_supported: ["header"],
      resource_name: deps.serverName ?? "secure-mcp-agent-starter",
    })
  })

  app.get("/healthz", (_req, res) => {
    res.json({ ok: true })
  })

  // 2. Every MCP request carries a bearer token that must have been minted FOR this server.
  const mcpAuth = requireBearerAuth({ verifier: deps.verifier, resourceMetadataUrl })

  /** Resolve an existing session and enforce that the caller is the identity that opened it. */
  const boundSession = (req: Request, res: Response): { id: string; transport: StreamableHTTPServerTransport } | null => {
    const id = req.header("mcp-session-id")
    const transport = id ? transports.get(id) : undefined
    const session = id ? sessions.get(id) : undefined
    if (!id || !transport || !session) {
      res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: no valid session" }, id: null })
      return null
    }
    const identity = req.auth ? identityFromAuthInfo(req.auth) : null
    if (!identity || !sessionMatchesIdentity(session, identity)) {
      if (identity) sessionEvent("agent.session.refused", id, identity, session.agentVersion, "session_identity_mismatch")
      res.status(403).json({ jsonrpc: "2.0", error: { code: -32000, message: "Forbidden: session belongs to another identity" }, id: null })
      return null
    }
    session.lastActivity = Date.now()
    return { id, transport }
  }

  app.post("/mcp", mcpAuth, async (req: Request, res: Response) => {
    const sessionId = req.header("mcp-session-id")

    if (sessionId) {
      const bound = boundSession(req, res)
      if (bound) await bound.transport.handleRequest(req, res, req.body)
      return
    }

    if (!isInitializeRequest(req.body)) {
      res.status(400).json({ jsonrpc: "2.0", error: { code: -32000, message: "Bad Request: no valid session" }, id: null })
      return
    }

    // New session. Its containment state is bound to the identity that opened it.
    const auth = req.auth
    if (!auth) {
      res.status(401).end()
      return
    }
    const identity = identityFromAuthInfo(auth)
    const agentConfig = Object.hasOwn(deps.manifest.agents, identity.clientId) ? deps.manifest.agents[identity.clientId] : undefined
    if (!agentConfig) {
      // An unknown client_id has no declared purpose, so it has no tools.
      sessionEvent("agent.session.refused", null, identity, "unknown", "unknown_agent")
      res.status(403).json({ error: "unknown_agent", message: `client ${identity.clientId} is not declared in the tool manifest` })
      return
    }
    if (sessions.countForSubject(identity.subject) >= maxSessionsPerSubject) {
      sessionEvent("agent.session.refused", null, identity, "unknown", "session_cap")
      res.status(429).json({ error: "too_many_sessions", message: `subject already holds ${maxSessionsPerSubject} sessions` })
      return
    }

    const allowed = new Set(agentConfig.tools)
    const server = new McpServer({ name: deps.serverName ?? "secure-mcp-agent-starter", version: deps.serverVersion ?? "0.1.0" })
    registerManifestTools(server, allowed, { ...deps, sessions })

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        transports.set(id, transport)
      },
      onsessionclosed: (id) => {
        transports.delete(id)
        sessions.delete(id)
      },
    })
    transport.onclose = () => {
      if (transport.sessionId) {
        transports.delete(transport.sessionId)
        sessions.delete(transport.sessionId)
      }
    }

    await server.connect(transport)
    await transport.handleRequest(req, res, req.body)

    // After the initialize round-trip the session id and client info are known.
    const id = transport.sessionId
    if (id) {
      const version = server.server.getClientVersion()?.version ?? "unknown"
      sessions.set(new SessionState(id, identity.clientId, version, identity.subject, identity.actor, allowed))
      sessionEvent("agent.session.opened", id, identity, version, null)
    }
  })

  const handleSessionRequest = async (req: Request, res: Response) => {
    const bound = boundSession(req, res)
    if (bound) await bound.transport.handleRequest(req, res)
  }
  app.get("/mcp", mcpAuth, handleSessionRequest)
  app.delete("/mcp", mcpAuth, handleSessionRequest)

  // 3. Human-in-the-loop approval. A separate identity (operator scope AND a
  //    different subject and client) approves the CONCRETE, schema-valid
  //    parameters of one pending call in one session. An agent token that
  //    happens to carry the operator scope cannot approve its own actions.
  const operatorAuth = requireBearerAuth({ verifier: deps.verifier, requiredScopes: [OPERATOR_SCOPE], resourceMetadataUrl })
  app.post("/admin/approvals", operatorAuth, (req: Request, res: Response) => {
    const parsed = ApprovalRequestSchema.safeParse(req.body)
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_request", issues: parsed.error.issues })
      return
    }
    const session = sessions.get(parsed.data.session_id)
    if (!session) {
      res.status(404).json({ error: "unknown_session" })
      return
    }
    const operator = req.auth ? identityFromAuthInfo(req.auth) : null
    if (!operator || operator.subject === session.subject || operator.clientId === session.agentId) {
      res.status(403).json({ error: "operator_not_separate", message: "the approving identity must differ from the session's user and agent" })
      return
    }
    const tool = deps.manifest.tools.find((t) => t.name === parsed.data.tool)
    if (!tool || tool.confirmation !== "human_in_the_loop" || !session.allowedTools.has(tool.name)) {
      res.status(400).json({ error: "tool_not_gated" })
      return
    }
    const args = validateApprovalArguments(tool, parsed.data.arguments)
    if (!args) {
      res.status(400).json({ error: "invalid_arguments", message: "arguments do not match the tool schema" })
      return
    }
    if (session.approvalCount >= 20) {
      res.status(429).json({ error: "too_many_pending_approvals" })
      return
    }
    const key = session.approve(tool.name, args)
    deps.audit({
      event: "agent.approval.granted",
      timestamp: new Date().toISOString(),
      session_id: session.sessionId,
      agent: { id: session.agentId, version: session.agentVersion },
      tool: tool.name,
      approval_key: `${session.sessionId}/${key}`,
      operator: { subject: operator.subject, client_id: operator.clientId },
    })
    res.status(201).json({ approval_key: `${session.sessionId}/${key}`, tool: tool.name, arguments: args })
  })

  return Object.assign(app, { closeSession })
}
