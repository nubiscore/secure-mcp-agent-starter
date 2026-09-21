/**
 * Sample agent client. Walks through the whole control set against a running
 * server and dev issuer:
 *
 *   pnpm dev:issuer   (terminal 1)
 *   pnpm dev:server   (terminal 2)
 *   pnpm dev:client   (terminal 3)
 *
 * There is no LLM in this loop on purpose. The point is to show what the
 * gateway does regardless of what a model asks for.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"

const ISSUER = (process.env.OAUTH_ISSUER ?? "http://localhost:3000").replace(/\/$/, "")
const MCP = (process.env.MCP_CANONICAL_URI ?? "http://localhost:3001").replace(/\/$/, "")

type MintArgs = { sub: string; client_id: string; scope: string; resource: string; act?: { sub: string } }

async function mint(args: MintArgs): Promise<string> {
  const res = await fetch(`${ISSUER}/dev/token`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(args) })
  if (!res.ok) throw new Error(`issuer refused: ${res.status} ${await res.text()}`)
  return ((await res.json()) as { access_token: string }).access_token
}

function step(title: string) {
  console.log(`\n=== ${title} ===`)
}

function show(label: string, value: unknown) {
  console.log(`${label}:`, typeof value === "string" ? value : JSON.stringify(value, null, 2))
}

async function connect(token: string, name = "agent-support-triage") {
  const client = new Client({ name, version: "2026.09.1" })
  const transport = new StreamableHTTPClientTransport(new URL(`${MCP}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  })
  await client.connect(transport)
  return { client, transport }
}

async function main() {
  step("0. Discover the resource server (RFC 9728)")
  const prm = await (await fetch(`${MCP}/.well-known/oauth-protected-resource`)).json()
  show("protected resource metadata", prm)

  step("1. Delegated token: user_88213, acting through agent-support-triage, audience = this server")
  const userToken = await mint({
    sub: "user_88213",
    client_id: "agent-support-triage",
    scope: "tickets:read tickets:comment kb:search billing:refund",
    resource: MCP,
    act: { sub: "spiffe://example.com/ns/ai-agents/sa/support-triage" },
  })
  const { client, transport } = await connect(userToken)
  const sessionId = transport.sessionId
  show("session", sessionId)

  step("2. Tools registered for this agent: only its declared purpose")
  const tools = await client.listTools()
  show("tools", tools.tools.map((t) => `${t.name}  [${t.annotations?.readOnlyHint ? "read-only" : t.annotations?.destructiveHint ? "DESTRUCTIVE" : "mutating"}]`))
  const indexerToken = await mint({ sub: "user_88213", client_id: "agent-kb-indexer", scope: "tickets:read tickets:comment kb:search billing:refund", resource: MCP })
  const indexer = await connect(indexerToken, "agent-kb-indexer")
  show("agent-kb-indexer sees (same scopes, narrower purpose)", (await indexer.client.listTools()).tools.map((t) => t.name))
  await indexer.transport.terminateSession()
  await indexer.client.close()

  step("3. Read own ticket (row-level auth against the delegating user)")
  show("get_ticket TKT-004821", (await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004821" } })).structuredContent)

  step("4. Read someone else's ticket: same scope, wrong subject")
  show("get_ticket TKT-004822", (await client.callTool({ name: "get_ticket", arguments: { ticket_id: "TKT-004822" } })).structuredContent)

  step("5. Search the KB: a poisoned document comes back wrapped and flagged")
  const kb = await client.callTool({ name: "search_kb", arguments: { query: "password" } })
  show("structured", kb.structuredContent)
  const first = (kb.content as Array<{ type: string; text?: string }>)[0]
  if (first?.type === "text") show("what the model sees", first.text)

  step("6. Comment on the ticket, recording which content triggered the decision")
  show(
    "post_ticket_comment",
    (
      await client.callTool({
        name: "post_ticket_comment",
        arguments: { ticket_id: "TKT-004821", body: "Refund approved per policy doc_1182" },
        _meta: { triggering_content_source: "kb:search#doc_1182" },
      })
    ).structuredContent,
  )

  step("7. Irreversible action without approval: contained, not executed")
  const refundArgs = { order_id: "ORD-88213", amount_cents: 41200, reason: "duplicate charge" }
  const blocked = await client.callTool({ name: "issue_refund", arguments: refundArgs })
  show("issue_refund", blocked.structuredContent)

  step("8. The agent cannot approve itself, even with the operator scope on its own token")
  const selfToken = await mint({ sub: "user_88213", client_id: "agent-support-triage", scope: "billing:refund agent:operate", resource: MCP, act: { sub: "spiffe://example.com/ns/ai-agents/sa/support-triage" } })
  const selfApprove = await fetch(`${MCP}/admin/approvals`, {
    method: "POST",
    headers: { "content-type": "application/json", Authorization: `Bearer ${selfToken}` },
    body: JSON.stringify({ session_id: sessionId, tool: "issue_refund", arguments: refundArgs }),
  })
  show(`self-approval -> HTTP ${selfApprove.status}`, await selfApprove.json())

  step("8b. On-call operator approves the CONCRETE parameters (separate identity, operator scope)")
  const operatorToken = await mint({ sub: "oncall_operator", client_id: "ops-console", scope: "agent:operate", resource: MCP })
  const approval = await fetch(`${MCP}/admin/approvals`, {
    method: "POST",
    headers: { "content-type": "application/json", Authorization: `Bearer ${operatorToken}` },
    body: JSON.stringify({ session_id: sessionId, tool: "issue_refund", arguments: refundArgs }),
  })
  show("approval", await approval.json())

  step("9. Retry with the approved parameters: allowed once")
  show("issue_refund", (await client.callTool({ name: "issue_refund", arguments: refundArgs })).structuredContent)

  step("10. Retry with DIFFERENT parameters: approval does not carry over")
  show("issue_refund (amount changed)", (await client.callTool({ name: "issue_refund", arguments: { ...refundArgs, amount_cents: 100 } })).structuredContent)

  step("10b. Read-then-exfiltrate: PII was read in step 3, so outbound email is contained, even in a NEW session")
  show("notify_customer (same session)", (await client.callTool({ name: "notify_customer", arguments: { ticket_id: "TKT-004821", body: "Your refund is on its way" } })).structuredContent)
  const again = await connect(userToken)
  show("notify_customer (fresh session)", (await again.client.callTool({ name: "notify_customer", arguments: { ticket_id: "TKT-004821", body: "Your refund is on its way" } })).structuredContent)
  await again.transport.terminateSession()
  await again.client.close()

  step("10c. Session binding: another user's token cannot drive or terminate this session")
  const otherUser = await mint({ sub: "user_11111", client_id: "agent-support-triage", scope: "tickets:read", resource: MCP })
  const hijack = await fetch(`${MCP}/mcp`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${otherUser}`, "mcp-session-id": sessionId ?? "" },
  })
  show(`DELETE by another user -> HTTP ${hijack.status}`, await hijack.text())

  await transport.terminateSession()
  await client.close()

  step("11. Token replay: a token minted for the finance server is rejected here")
  const financeToken = await mint({ sub: "user_88213", client_id: "agent-support-triage", scope: "tickets:read", resource: "https://finance.example.com" })
  try {
    await connect(financeToken)
    console.log("UNEXPECTED: replayed token accepted")
  } catch (err) {
    show("rejected", err instanceof Error ? err.message : err)
  }

  step("12. Undeclared agent: valid token, but no purpose in the manifest")
  const rogueToken = await mint({ sub: "user_88213", client_id: "agent-rogue", scope: "tickets:read", resource: MCP })
  try {
    await connect(rogueToken, "agent-rogue")
    console.log("UNEXPECTED: undeclared agent accepted")
  } catch (err) {
    show("rejected", err instanceof Error ? err.message : err)
  }

  console.log("\nDone. Check the server terminal for one audit event per call.")
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
