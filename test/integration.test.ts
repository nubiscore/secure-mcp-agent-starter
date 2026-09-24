import { afterAll, beforeAll, describe, expect, it } from "vitest"
import type { Server } from "node:http"
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import type { AuditEvent, ToolInvokedEvent } from "../src/audit/events.js"
import { createTokenVerifier } from "../src/auth/verify-token.js"
import { MemoryFlagStore } from "../src/policy/kill-switch.js"
import { MemoryRateLimiter } from "../src/policy/rate-limit.js"
import { createApp } from "../src/server.js"
import { createHandlers, InMemoryStore } from "../src/tools/handlers.js"
import { hashManifest, loadManifest } from "../src/tools/manifest.js"
import { createTestIssuer, TEST_ISSUER, TEST_RESOURCE, type TestIssuer } from "./helpers.js"

const ALL_SCOPES = "tickets:read tickets:comment kb:search billing:refund"
const AGENT = "agent-support-triage"
const ACTOR = "spiffe://test/agent"

describe("gateway end to end", () => {
  let issuer: TestIssuer
  let http: Server
  let base: string
  const flags = new MemoryFlagStore()
  const events: AuditEvent[] = []
  const toolEvents = () => events.filter((e): e is ToolInvokedEvent => e.event === "agent.tool.invoked")

  beforeAll(async () => {
    issuer = await createTestIssuer()
    const manifest = loadManifest("tools/manifest.yaml")
    // Tighten one rate limit so the gateway wiring can be exercised quickly.
    const comment = manifest.tools.find((t) => t.name === "post_ticket_comment")!
    comment.rate_limit = "2/hour"
    const app = createApp({
      manifest,
      manifestHash: hashManifest(manifest),
      handlers: createHandlers(new InMemoryStore()),
      flags,
      rateLimiter: new MemoryRateLimiter(),
      budget: { maxIterations: 50, maxToolCalls: 50, maxTokens: 1000, maxMutations: 3 },
      audit: (e) => events.push(e),
      canonicalUri: TEST_RESOURCE,
      issuer: TEST_ISSUER,
      verifier: createTokenVerifier({ issuer: TEST_ISSUER, canonicalUri: TEST_RESOURCE, jwks: issuer.getKey }),
      maxSessionsPerSubject: 2,
      sweepIntervalMs: 0,
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

  const mint = (over: Partial<Parameters<TestIssuer["mint"]>[0]> = {}) =>
    issuer.mint({ sub: "user_88213", client_id: AGENT, scope: ALL_SCOPES, act: { sub: ACTOR }, ...over })

  async function connect(token: string, name = AGENT) {
    const client = new Client({ name, version: "test.1" })
    const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } })
    await client.connect(transport)
    return { client, transport }
  }

  const rpc = (token: string, sessionId: string, method: string, params: unknown, httpMethod = "POST") =>
    fetch(`${base}/mcp`, {
      method: httpMethod,
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", Authorization: `Bearer ${token}`, "mcp-session-id": sessionId },
      body: httpMethod === "POST" ? JSON.stringify({ jsonrpc: "2.0", id: 99, method, params }) : undefined,
    })

  const approve = (token: string, sessionId: string, tool: string, args: Record<string, unknown>) =>
    fetch(`${base}/admin/approvals`, {
      method: "POST",
      headers: { "content-type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ session_id: sessionId, tool, arguments: args }),
    })

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
    await expect(connect(await mint({ aud: "https://finance.test" }))).rejects.toThrow(/invalid_token.*aud/)
  })

  it("rejects an agent that is not declared in the manifest, including prototype names", async () => {
    await expect(connect(await mint({ client_id: "agent-rogue" }), "agent-rogue")).rejects.toThrow(/unknown_agent/)
    await expect(connect(await mint({ client_id: "constructor" }), "constructor")).rejects.toThrow(/unknown_agent/)
  })

  it("registers only the agent's declared tools for its session", async () => {
    const { client, transport } = await connect(await mint({ client_id: "agent-kb-indexer", scope: ALL_SCOPES }), "agent-kb-indexer")
    const tools = await client.listTools()
    expect(tools.tools.map((t) => t.name)).toEqual(["search_kb"])
    await transport.terminateSession()
    await client.close()
  })

  it("runs the full delegated flow: row-level auth, central envelope, approvals, binding, kill switch, audit", async () => {
    const token = await mint()
    const { client, transport } = await connect(token)
    const sessionId = transport.sessionId!
    expect(sessionId).toBeTruthy()

    const tools = await client.listTools()
    expect(tools.tools.map((t) => t.name).sort()).toEqual(["get_ticket", "issue_refund", "notify_customer", "post_ticket_comment", "search_kb"])
    expect(tools.tools.find((t) => t.name === "issue_refund")?.annotations?.destructiveHint).toBe(true)

    // Own ticket: ok. Someone else's: not found, even though the scope is present.
    const own = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004821" } })
    expect(own.structuredContent).toMatchObject({ id: "TKT-004821", owner: "user_88213" })
    const other = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004822" } })
    expect(other.structuredContent).toEqual({ error: "not_found" })

    // Schema enforcement happens before the handler runs.
    const invalid = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "1 OR 1=1" } })
    expect(invalid.isError).toBe(true)
    expect(JSON.stringify(invalid.content)).toContain("Input validation error")

    // Poisoned KB document is stripped and flagged BY THE GATEWAY, including structured fields.
    const kb = await client.callTool({ name: "search_kb", arguments: { query: "password" } })
    expect(kb.structuredContent).toMatchObject({ source: "kb:search#doc_2210", suspicious: true, title: "Community FAQ (user-submitted)" })
    const text = kb.content[0]
    expect(text?.type === "text" && text.text).toContain('<untrusted_content source="kb:search#doc_2210">')
    expect(text?.type === "text" && text.text).not.toContain("IGNORE ALL PREVIOUS")

    // Irreversible action is contained until a human approves the exact parameters.
    const args = { order_id: "ORD-88213", amount_cents: 1000, reason: "dup" }
    const blocked = await client.callTool({ name: "issue_refund", arguments: args })
    expect(blocked.isError).toBe(true)
    expect(blocked.structuredContent).toMatchObject({ error: "contained", reason: "human_approval_required", tool: "issue_refund" })

    // The agent's own token cannot approve: without the scope, and even WITH it.
    expect((await approve(token, sessionId, "issue_refund", args)).status).toBe(403)
    const selfWithScope = await mint({ scope: `${ALL_SCOPES} agent:operate` })
    const self = await approve(selfWithScope, sessionId, "issue_refund", args)
    expect(self.status).toBe(403)
    expect(await self.json()).toMatchObject({ error: "operator_not_separate" })

    // A separate operator can, but only with schema-valid arguments for a gated tool.
    const operator = await issuer.mint({ sub: "oncall", client_id: "ops-console", scope: "agent:operate" })
    expect((await approve(operator, sessionId, "issue_refund", { order_id: "DROP TABLE", amount_cents: 999999999 })).status).toBe(400)
    expect((await approve(operator, sessionId, "get_ticket", { ticket_id: "TKT-004821" })).status).toBe(400)
    expect((await approve(operator, "no-such-session", "issue_refund", args)).status).toBe(404)
    const approved = await approve(operator, sessionId, "issue_refund", args)
    expect(approved.status).toBe(201)

    const ok = await client.callTool({ name: "issue_refund", arguments: args })
    expect(ok.isError).toBeFalsy()
    expect(ok.structuredContent).toMatchObject({ order_id: "ORD-88213", refunded_cents: 1000 })

    // Approval is single-use and parameter-bound.
    expect((await client.callTool({ name: "issue_refund", arguments: args })).structuredContent).toMatchObject({ reason: "human_approval_required" })
    expect((await client.callTool({ name: "issue_refund", arguments: { ...args, amount_cents: 999 } })).structuredContent).toMatchObject({ reason: "human_approval_required" })

    // Read-then-exfiltrate: PII was read above, so the egress tool is contained
    // before it even reaches the approval gate.
    const egress = await client.callTool({ name: "notify_customer", arguments: { ticket_id: "TKT-004821", body: "hi" } })
    expect(egress.structuredContent).toMatchObject({ error: "contained", reason: "egress_after_pii" })

    // ...and opening a fresh session does not launder it.
    const fresh = await connect(token)
    const laundered = await fresh.client.callTool({ name: "notify_customer", arguments: { ticket_id: "TKT-004821", body: "hi" } })
    expect(laundered.structuredContent).toMatchObject({ reason: "egress_after_pii" })
    await fresh.transport.terminateSession()
    await fresh.client.close()

    // Session binding: another user, or another agent for the same user, or the
    // same agent without its workload identity, cannot drive this session.
    const otherUser = await mint({ sub: "user_11111" })
    const otherAgent = await mint({ client_id: "agent-kb-indexer" })
    const noActor = await issuer.mint({ sub: "user_88213", client_id: AGENT, scope: ALL_SCOPES })
    for (const t of [otherUser, otherAgent, noActor]) {
      const res = await rpc(t, sessionId, "tools/call", { name: "get_ticket", arguments: { ticket_id: "TKT-004822" } })
      expect(res.status).toBe(403)
      expect(await res.text()).toContain("another identity")
    }
    // Nor terminate it.
    expect((await rpc(otherUser, sessionId, "", undefined, "DELETE")).status).toBe(403)
    expect((await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004821" } })).isError).toBeFalsy()

    // Rate limit through the HTTP path (2/hour for comments in this test).
    const commentArgs = { ticket_id: "TKT-004821", body: "x" }
    expect((await client.callTool({ name: "post_ticket_comment", arguments: commentArgs })).isError).toBeFalsy()
    expect((await client.callTool({ name: "post_ticket_comment", arguments: commentArgs })).isError).toBeFalsy()
    expect((await client.callTool({ name: "post_ticket_comment", arguments: commentArgs })).structuredContent).toMatchObject({ reason: "rate_limited" })

    // Kill switch takes effect mid-session.
    flags.flags = { disabled_agents: [AGENT] }
    expect((await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004821" } })).structuredContent).toMatchObject({ reason: "agent_disabled" })
    flags.flags = {}

    // Advisory token hint can only tighten containment.
    const spent = await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004821" }, _meta: { tokens_used: 5000 } })
    expect(spent.structuredContent).toMatchObject({ reason: "token_budget" })

    await transport.terminateSession()
    await client.close()

    // Audit trail: every call produced an event with the delegation chain.
    const forSession = toolEvents().filter((e) => e.session_id === sessionId)
    expect(forSession.length).toBeGreaterThanOrEqual(14)
    expect(forSession.every((e) => e.identity.on_behalf_of === "user_88213")).toBe(true)
    expect(forSession.some((e) => e.decision.reason === "human_approval_required")).toBe(true)
    expect(forSession.some((e) => e.decision.reason === "egress_after_pii")).toBe(true)
    expect(forSession.some((e) => e.decision.policy === "rate_limited")).toBe(true)
    const success = forSession.find((e) => e.tool.name === "issue_refund" && e.outcome.status === "success")
    expect(success?.decision.human_approval).toMatch(/^.+\/issue_refund:[0-9a-f]{64}$/)
    expect(success?.identity.workload).toBe(ACTOR)
    expect(forSession.every((e) => e.tool.manifest_hash.startsWith("sha256:"))).toBe(true)
    // Binding refusals and approvals go through the same sink.
    expect(events.filter((e) => e.event === "agent.session.refused" && e.reason === "session_identity_mismatch").length).toBeGreaterThanOrEqual(4)
    const granted = events.find((e) => e.event === "agent.approval.granted")
    expect(granted && granted.event === "agent.approval.granted" && granted.operator).toEqual({ subject: "oncall", client_id: "ops-console" })
  })

  it("blocks egress in a session opened BEFORE another session read PII", async () => {
    // user_11111 owns TKT-004822 and has not read PII in this suite yet.
    const token = await mint({ sub: "user_11111" })
    const early = await connect(token)
    const reader = await connect(token)
    const notifyArgs = { ticket_id: "TKT-004822", body: "status update" }

    // Before the read, the early session only needs approval.
    expect((await early.client.callTool({ name: "notify_customer", arguments: notifyArgs })).structuredContent).toMatchObject({ reason: "human_approval_required" })
    expect((await reader.client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004822" } })).isError).toBeFalsy()

    // After it, even an approved call from the earlier session is contained.
    const operator = await issuer.mint({ sub: "oncall", client_id: "ops-console", scope: "agent:operate" })
    expect((await approve(operator, early.transport.sessionId!, "notify_customer", notifyArgs)).status).toBe(201)
    expect((await early.client.callTool({ name: "notify_customer", arguments: notifyArgs })).structuredContent).toMatchObject({ reason: "egress_after_pii" })

    for (const s of [early, reader]) {
      await s.transport.terminateSession()
      await s.client.close()
    }
  })

  it("counts irreversible actions across sessions that were already open", async () => {
    const token = await mint()
    const early = await connect(token)
    const spender = await connect(token)
    const operator = await issuer.mint({ sub: "oncall", client_id: "ops-console", scope: "agent:operate" })

    // Spend the (subject, agent) mutation budget in one session...
    let reason: unknown
    for (let i = 0; i < 5 && reason !== "mutation_cap"; i++) {
      const args = { order_id: "ORD-88213", amount_cents: 1, reason: `spend-${i}` }
      await approve(operator, spender.transport.sessionId!, "issue_refund", args)
      const res = await spender.client.callTool({ name: "issue_refund", arguments: args })
      reason = res.isError ? (res.structuredContent as { reason?: unknown }).reason : undefined
    }
    expect(reason).toBe("mutation_cap")

    // ...and the session opened before that spend is capped too, approval or not.
    const args = { order_id: "ORD-88213", amount_cents: 1, reason: "early" }
    expect((await approve(operator, early.transport.sessionId!, "issue_refund", args)).status).toBe(201)
    expect((await early.client.callTool({ name: "issue_refund", arguments: args })).structuredContent).toMatchObject({ reason: "mutation_cap" })

    const ids = [early.transport.sessionId, spender.transport.sessionId]
    for (const s of [early, spender]) {
      await s.transport.terminateSession()
      await s.client.close()
    }
    // Every session that closed left a matching audit event.
    const closed = events.filter((e) => e.event === "agent.session.closed").map((e) => e.session_id)
    expect(closed).toEqual(expect.arrayContaining(ids))
  })

  it("refuses a tool whose scope the token lacks, even for a declared agent", async () => {
    const { client, transport } = await connect(await mint({ scope: "tickets:read" }))
    const res = await client.callTool({ name: "issue_refund", arguments: { order_id: "ORD-88213", amount_cents: 1, reason: "x" } })
    expect(res.structuredContent).toMatchObject({ error: "insufficient_scope" })
    await transport.terminateSession()
    await client.close()
  })

  it("caps concurrent sessions per subject", async () => {
    const token = await mint({ sub: "user_cap" })
    const a = await connect(token)
    const b = await connect(token)
    await expect(connect(token)).rejects.toThrow(/too_many_sessions/)
    await a.transport.terminateSession()
    await b.transport.terminateSession()
    await a.client.close()
    await b.client.close()
    // Freed, so a new one is accepted.
    const c = await connect(token)
    await c.transport.terminateSession()
    await c.client.close()
  })
})
