import { randomUUID } from "node:crypto"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import { z } from "zod"
import { identityFromAuthInfo } from "../auth/verify-token.js"
import { redactArguments, type AuditEvent, type AuditSink } from "../audit/events.js"
import { check, Contained, type SessionBudget } from "../policy/containment.js"
import type { FlagStore } from "../policy/kill-switch.js"
import type { RateLimiter } from "../policy/rate-limit.js"
import type { SessionState, SessionStore } from "../policy/session.js"
import type { ToolHandler } from "./handlers.js"
import { parametersToZodShape, type Manifest, type ToolDefinition } from "./manifest.js"

export type GatewayDeps = {
  manifest: Manifest
  manifestHash: string
  handlers: Record<string, ToolHandler>
  sessions: SessionStore
  flags: FlagStore
  rateLimiter: RateLimiter
  budget: SessionBudget
  audit: AuditSink
  canonicalUri: string
}

/**
 * The gateway. Every tool the model can see is registered through here, and
 * every call passes through the same sequence:
 *
 *   scope check -> session binding -> containment -> rate limit -> handler -> audit
 *
 * Nothing in this sequence depends on the model's cooperation.
 */
export function registerManifestTools(server: McpServer, deps: GatewayDeps): void {
  for (const tool of deps.manifest.tools) {
    const handler = deps.handlers[tool.name]
    if (!handler) throw new Error(`manifest declares ${tool.name} but no handler is registered`)

    server.registerTool(
      tool.name,
      {
        description: tool.purpose,
        inputSchema: parametersToZodShape(tool.parameters),
        annotations: {
          readOnlyHint: !tool.mutating,
          destructiveHint: tool.mutating && tool.reversible === false,
          idempotentHint: !tool.mutating,
          openWorldHint: Boolean(tool.external_egress || tool.untrusted_output),
        },
      },
      async (args: Record<string, unknown>, extra): Promise<CallToolResult> => {
        const started = Date.now()
        const traceId = randomUUID().replace(/-/g, "")
        const sessionId = extra.sessionId ?? "stateless"
        const authInfo = extra.authInfo
        if (!authInfo) return errorResult("unauthenticated", "no verified identity on request")
        const identity = identityFromAuthInfo(authInfo)
        const session = deps.sessions.get(sessionId)
        if (!session) return errorResult("no_session", "session not initialised")

        const meta = (extra._meta ?? {}) as { triggering_content_source?: unknown }
        const triggering = typeof meta.triggering_content_source === "string" ? meta.triggering_content_source : null
        const firstUse = !session.toolsUsed.has(tool.name)

        const base = (): Omit<AuditEvent, "decision" | "outcome"> => ({
          event: "agent.tool.invoked",
          timestamp: new Date().toISOString(),
          trace_id: traceId,
          session_id: sessionId,
          agent: { id: session.agentId, version: session.agentVersion },
          identity: {
            workload: identity.actor,
            on_behalf_of: identity.subject,
            token_audience: deps.canonicalUri,
            scopes: identity.scopes,
          },
          tool: {
            name: tool.name,
            server: new URL(deps.canonicalUri).host,
            manifest_hash: deps.manifestHash,
            arguments_redacted: redactArguments(tool, args),
            mutating: tool.mutating,
            reversible: tool.reversible,
            first_use_in_session: firstUse,
          },
        })

        // 0. Session binding: a session opened for one user cannot be driven
        //    with another user's token. Logged, because it is an attack signal.
        if (session.subject !== identity.subject) {
          deps.audit({
            ...base(),
            decision: { iteration: session.iterations, triggering_content_source: triggering, policy: "contained", reason: "session_identity_mismatch", human_approval: null },
            outcome: { status: "contained", latency_ms: Date.now() - started },
          })
          return errorResult("session_identity_mismatch", "token subject does not match session")
        }

        // 1. Scope: the token must carry the tool's required scope.
        if (!identity.scopes.includes(tool.required_scope)) {
          deps.audit({
            ...base(),
            decision: { iteration: session.iterations, triggering_content_source: triggering, policy: "contained", reason: "insufficient_scope", human_approval: null },
            outcome: { status: "contained", latency_ms: Date.now() - started },
          })
          return errorResult("insufficient_scope", `tool requires scope ${tool.required_scope}`)
        }

        // 2. Containment, before the call, every call.
        try {
          check(session, tool, args, deps.budget, deps.flags)
        } catch (err) {
          if (err instanceof Contained) {
            deps.audit({
              ...base(),
              decision: { iteration: session.iterations, triggering_content_source: triggering, policy: "contained", reason: err.reason, human_approval: null },
              outcome: { status: "contained", latency_ms: Date.now() - started },
            })
            return containedResult(err)
          }
          throw err
        }

        // 3. Rate limit per tool per delegating user.
        if (tool.rate_limit && !deps.rateLimiter.take(`${tool.name}:${identity.subject}`, tool.rate_limit)) {
          deps.audit({
            ...base(),
            decision: { iteration: session.iterations, triggering_content_source: triggering, policy: "rate_limited", reason: tool.rate_limit, human_approval: null },
            outcome: { status: "contained", latency_ms: Date.now() - started },
          })
          return containedResult(new Contained("rate_limited", `rate limit ${tool.rate_limit} exceeded for ${tool.name}`))
        }

        // 4. Account for the call, then run the handler.
        session.toolCalls += 1
        session.iterations += 1
        session.toolsUsed.add(tool.name)
        if (tool.touches_pii) session.touchedPii = true
        let approvalKey: string | null = null
        if (tool.mutating && tool.reversible === false) {
          approvalKey = SessionStateApprovalKey(session, tool, args)
          session.consumeApproval(tool.name, args)
          session.mutations += 1
        }

        try {
          const result = await handler(args, { identity, sessionId })
          deps.audit({
            ...base(),
            decision: { iteration: session.iterations, triggering_content_source: triggering, policy: "allow", reason: null, human_approval: approvalKey },
            outcome: { status: "success", latency_ms: Date.now() - started },
          })
          const out: CallToolResult = { content: [{ type: "text", text: result.text }] }
          if (result.structured) out.structuredContent = result.structured
          return out
        } catch (err) {
          deps.audit({
            ...base(),
            decision: { iteration: session.iterations, triggering_content_source: triggering, policy: "error", reason: err instanceof Error ? err.name : "unknown", human_approval: approvalKey },
            outcome: { status: "error", latency_ms: Date.now() - started },
          })
          // Never leak internals to the model; it is an untrusted consumer too.
          return errorResult("tool_error", "tool execution failed")
        }
      },
    )
  }
}

function SessionStateApprovalKey(session: SessionState, tool: ToolDefinition, args: Record<string, unknown>): string {
  return `${session.sessionId}/${(session.constructor as typeof SessionState).approvalKey(tool.name, args)}`
}

function errorResult(code: string, message: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text: `${code}: ${message}` }], structuredContent: { error: code, message } }
}

/**
 * A Contained result is returned to the client as an error result with a
 * machine-readable reason. The agent loop is expected to stop and escalate,
 * not retry. For human_approval_required the concrete parameters and the
 * approval key are included so an operator can approve exactly this call.
 */
function containedResult(err: Contained): CallToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: `contained (${err.reason}): ${err.message}` }],
    structuredContent: { error: "contained", reason: err.reason, message: err.message, ...err.detail },
  }
}

export const ApprovalRequestSchema = z.object({
  session_id: z.string().min(1),
  tool: z.string().min(1),
  arguments: z.record(z.string(), z.unknown()),
})
