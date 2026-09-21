import { randomUUID } from "node:crypto"
import express, { type Request, type Response } from "express"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js"
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js"
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js"
import { identityFromAuthInfo } from "./auth/verify-token.js"
import { SessionState, SessionStore } from "./policy/session.js"
import { ApprovalRequestSchema, registerManifestTools, type GatewayDeps } from "./tools/registry.js"

export const OPERATOR_SCOPE = "agent:operate"

export type AppDeps = Omit<GatewayDeps, "sessions"> & {
  verifier: OAuthTokenVerifier
  issuer: string
  sessions?: SessionStore
  serverName?: string
  serverVersion?: string
}

/**
 * Builds the Express app. Routes:
 *
 *   GET  /.well-known/oauth-protected-resource   RFC 9728 metadata (unauthenticated, by design)
 *   POST /mcp                                     MCP Streamable HTTP (bearer token required)
 *   GET  /mcp, DELETE /mcp                        SSE stream / session close (bearer token required)
 *   POST /admin/approvals                         Human-in-the-loop approval (operator scope required)
 *   GET  /healthz
 */
export function createApp(deps: AppDeps) {
  const sessions = deps.sessions ?? new SessionStore()
  const transports = new Map<string, StreamableHTTPServerTransport>()
  const app = express()
  app.disable("x-powered-by")
  app.use(express.json({ limit: "256kb" }))

  const resourceMetadataUrl = `${deps.canonicalUri}/.well-known/oauth-protected-resource`

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
    res.json({ ok: true, manifest_hash: deps.manifestHash })
  })

  // 2. Every MCP request carries a bearer token that must have been minted FOR this server.
  const mcpAuth = requireBearerAuth({ verifier: deps.verifier, resourceMetadataUrl })

  app.post("/mcp", mcpAuth, async (req: Request, res: Response) => {
    const sessionId = req.header("mcp-session-id")
    const existing = sessionId ? transports.get(sessionId) : undefined

    if (existing) {
      await existing.handleRequest(req, res, req.body)
      return
    }

    if (sessionId || !isInitializeRequest(req.body)) {
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
    const agentConfig = deps.manifest.agents[identity.clientId]
    if (!agentConfig) {
      // An unknown client_id has no declared purpose, so it has no tools.
      res.status(403).json({ error: "unknown_agent", message: `client ${identity.clientId} is not declared in the tool manifest` })
      return
    }

    const server = new McpServer({ name: deps.serverName ?? "secure-mcp-agent-starter", version: deps.serverVersion ?? "0.1.0" })
    registerManifestTools(server, { ...deps, sessions })

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
      const client = server.server.getClientVersion()
      sessions.set(new SessionState(id, identity.clientId, client?.version ?? "unknown", identity.subject, new Set(agentConfig.tools)))
    }
  })

  const handleSessionRequest = async (req: Request, res: Response) => {
    const sessionId = req.header("mcp-session-id")
    const transport = sessionId ? transports.get(sessionId) : undefined
    if (!transport) {
      res.status(400).send("Invalid or missing session ID")
      return
    }
    await transport.handleRequest(req, res)
  }
  app.get("/mcp", mcpAuth, handleSessionRequest)
  app.delete("/mcp", mcpAuth, handleSessionRequest)

  // 3. Human-in-the-loop approval. A separate identity (operator scope) approves
  //    the CONCRETE parameters of one pending call in one session. The agent's
  //    own token cannot approve its own actions.
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
    const tool = deps.manifest.tools.find((t) => t.name === parsed.data.tool)
    if (!tool || tool.confirmation !== "human_in_the_loop") {
      res.status(400).json({ error: "tool_not_gated" })
      return
    }
    const key = session.approve(tool.name, parsed.data.arguments)
    const operator = req.auth ? identityFromAuthInfo(req.auth).subject : "unknown"
    process.stdout.write(
      JSON.stringify({ event: "agent.approval.granted", timestamp: new Date().toISOString(), session_id: session.sessionId, tool: tool.name, approval_key: key, operator }) + "\n",
    )
    res.status(201).json({ approval_key: `${session.sessionId}/${key}`, tool: tool.name, arguments: parsed.data.arguments })
  })

  return app
}
