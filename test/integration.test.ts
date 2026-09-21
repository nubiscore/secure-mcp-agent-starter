import { afterAll, beforeAll, describe, expect, it } from "vitest"
import type { Server } from "node:http"
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import type { AuditEvent } from "../src/audit/events.js"
import { createTokenVerifier } from "../src/auth/verify-token.js"
import { MemoryFlagStore } from "../src/policy/kill-switch.js"
import { MemoryRateLimiter } from "../src/policy/rate-limit.js"
import { createApp } from "../src/server.js"
import { createHandlers, InMemoryStore } from "../src/tools/handlers.js"
import { hashManifest, loadManifest } from "../src/tools/manifest.js"
import { createTestIssuer, TEST_ISSUER, TEST_RESOURCE, type TestIssuer } from "./helpers.js"

const ALL_SCOPES = "tickets:read tickets:comment kb:search billing:refund"

describe("gateway end to end", () => {
  let issuer: TestIssuer
  let http: Server
  let base: string
  const flags = new MemoryFlagStore()
  const events: AuditEvent[] = []

  beforeAll(async () => {
    issuer = await createTestIssuer()
    const manifest = loadManifest("tools/manifest.yaml")
    const app = createApp({
      manifest,
      manifestHash: hashManifest(manifest),
      handlers: createHandlers(new InMemoryStore()),
      flags,
      rateLimiter: new MemoryRateLimiter(),
      budget: { maxIterations: 50, maxToolCalls: 50, maxTokens: 1_000_000, maxMutations: 3 },
      audit: (e) => events.push(e),
      canonicalUri: TEST_RESOURCE,
      issuer: TEST_ISSUER,
      verifier: createTokenVerifier({ issuer: TEST_ISSUER, canonicalUri: TEST_RESOURCE, jwks: issuer.getKey }),
    })
    await new Promise<void>((resolve) => {
      http = app.listen(0, "127.0.0.1", () => resolve())
    })
    const addr = http.address()
    if (!addr || typeof addr === "string") throw new Error("no address")
    base = `http://127.0.0.1:${addr.port}`
  })

  afterAll(async () => {
    await new Promise<void>((resolve) => http.close(() => resolve()))
  })

  async function connect(token: string, name = "agent-support-triage") {
    const client = new Client({ name, version: "test.1" })
    const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } })
    await client.connect(transport)
    return { client, transport }
  }

  it("publishes protected resource metadata without authentication", async () => {
    const res = await fetch(`${base}/.well-known/oauth-protected-resource`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as { resource: string; authorization_servers: string[]; scopes_supported: string[] }
    expect(body.resource).toBe(TEST_RESOURCE)
    expect(body.authorization_servers).toEqual([TEST_ISSUER])
    expect(body.scopes_supported).toContain("billing:refund")
  })

  it("refuses MCP requests without a token and points at the metadata", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })
    expect(res.status).toBe(401)
    expect(res.headers.get("www-authenticate")).toContain("resource_metadata=")
  })

  it("rejects a token minted for another resource server", async () => {
    const token = await issuer.mint({ sub: "user_88213", client_id: "agent-support-triage", scope: ALL_SCOPES, aud: "https://finance.test" })
    await expect(connect(token)).rejects.toThrow(/invalid_token.*aud/)
  })

  it("rejects an agent that is not declared in the manifest", async () => {
    const token = await issuer.mint({ sub: "user_88213", client_id: "agent-rogue", scope: ALL_SCOPES })
    await expect(connect(token, "agent-rogue")).rejects.toThrow(/unknown_agent/)
  })

  it("runs the full delegated flow with row-level auth, scope checks, approval gating, and audit", async () => {
    const token = await issuer.mint({ sub: "user_88213", client_id: "agent-support-triage", scope: ALL_SCOPES, act: { sub: "spiffe://test/agent" } })
    const { client, transport } = await connect(token)
    const sessionId = transport.sessionId
    expect(sessionId).toBeTruthy()

    const tools = await client.listTools()
    expect(tools.tools.map((t) => t.name).sort()).toEqual(["get_ticket", "issue_refund", "post_ticket_comment", "search_kb"])
    const refund = tools.tools.find((t) => t.name === "issue_refund")
    expect(refund?.annotations?.destructiveHint).toBe(true)

    // Own ticket: ok. Someone else's: not found, even though the scope is present.
    const own = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004821" } })
    expect(own.structuredContent).toMatchObject({ id: "TKT-004821", owner: "user_88213" })
    const other = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004822" } })
    expect(other.structuredContent).toEqual({ error: "not_found" })

    // Schema enforcement happens before the handler runs.
    const invalid = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "1 OR 1=1" } })
    expect(invalid.isError).toBe(true)
    expect(JSON.stringify(invalid.content)).toContain("Input validation error")

    // Poisoned KB document is stripped and flagged.
    const kb = await client.callTool({ name: "search_kb", arguments: { query: "password" } })
    expect(kb.structuredContent).toMatchObject({ source: "kb:search#doc_2210", suspicious: true })
    const text = kb.content[0]
    expect(text?.type === "text" && text.text).toContain('<untrusted_content source="kb:search#doc_2210">')
    expect(text?.type === "text" && text.text).not.toContain("IGNORE ALL PREVIOUS")

    // Irreversible action is contained until a human approves the exact parameters.
    const args = { order_id: "ORD-88213", amount_cents: 1000, reason: "dup" }
    const blocked = await client.callTool({ name: "issue_refund", arguments: args })
    expect(blocked.isError).toBe(true)
    expect(blocked.structuredContent).toMatchObject({ error: "contained", reason: "human_approval_required", tool: "issue_refund" })

    // The agent's own token cannot approve.
    const selfApprove = await fetch(`${base}/admin/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ session_id: sessionId, tool: "issue_refund", arguments: args }),
    })
    expect(selfApprove.status).toBe(403)

    // An operator can.
    const operator = await issuer.mint({ sub: "oncall", client_id: "ops-console", scope: "agent:operate" })
    const approved = await fetch(`${base}/admin/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json", Authorization: `Bearer ${operator}` },
      body: JSON.stringify({ session_id: sessionId, tool: "issue_refund", arguments: args }),
    })
    expect(approved.status).toBe(201)

    const ok = await client.callTool({ name: "issue_refund", arguments: args })
    expect(ok.isError).toBeFalsy()
    expect(ok.structuredContent).toMatchObject({ order_id: "ORD-88213", refunded_cents: 1000 })

    // Approval is single-use and parameter-bound.
    const again = await client.callTool({ name: "issue_refund", arguments: args })
    expect(again.structuredContent).toMatchObject({ reason: "human_approval_required" })
    const changed = await client.callTool({ name: "issue_refund", arguments: { ...args, amount_cents: 999 } })
    expect(changed.structuredContent).toMatchObject({ reason: "human_approval_required" })

    // A different user's token cannot drive this session.
    const otherUser = await issuer.mint({ sub: "user_11111", client_id: "agent-support-triage", scope: ALL_SCOPES })
    const hijack = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", Authorization: `Bearer ${otherUser}`, "mcp-session-id": sessionId! },
      body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "tools/call", params: { name: "get_ticket", arguments: { ticket_id: "TKT-004822" } } }),
    })
    const hijackText = await hijack.text()
    expect(hijackText).toContain("session_identity_mismatch")

    // Kill switch takes effect mid-session.
    flags.flags = { disabled_agents: ["agent-support-triage"] }
    const killed = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004821" } })
    expect(killed.structuredContent).toMatchObject({ error: "contained", reason: "agent_disabled" })
    flags.flags = {}

    await transport.terminateSession()
    await client.close()

    // Audit trail: every call produced an event with the delegation chain.
    const forSession = events.filter((e) => e.session_id === sessionId)
    expect(forSession.length).toBeGreaterThanOrEqual(9)
    expect(forSession.every((e) => e.identity.on_behalf_of === "user_88213" || e.identity.on_behalf_of === "user_11111")).toBe(true)
    expect(forSession.some((e) => e.decision.policy === "contained" && e.decision.reason === "human_approval_required")).toBe(true)
    const success = forSession.find((e) => e.tool.name === "issue_refund" && e.outcome.status === "success")
    expect(success?.decision.human_approval).toMatch(/^.+\/issue_refund:[0-9a-f]{64}$/)
    expect(success?.identity.workload).toBe("spiffe://test/agent")
    expect(forSession.every((e) => e.tool.manifest_hash.startsWith("sha256:"))).toBe(true)
  })

  it("refuses a tool whose scope the token lacks, even for a declared agent", async () => {
    const token = await issuer.mint({ sub: "user_88213", client_id: "agent-support-triage", scope: "tickets:read" })
    const { client, transport } = await connect(token)
    const res = await client.callTool({ name: "issue_refund", arguments: { order_id: "ORD-88213", amount_cents: 1, reason: "x" } })
    expect(res.structuredContent).toMatchObject({ error: "insufficient_scope" })
    await transport.terminateSession()
    await client.close()
  })
})
