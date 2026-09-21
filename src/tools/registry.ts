import { randomUUID } from "node:crypto"
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js"
import { z } from "zod"
import { identityFromAuthInfo, type VerifiedIdentity } from "../auth/verify-token.js"
import { redactArguments, type AuditSink, type ToolInvokedEvent } from "../audit/events.js"
import { check, Contained, type SessionBudget } from "../policy/containment.js"
import type { FlagStore } from "../policy/kill-switch.js"
import type { RateLimiter } from "../policy/rate-limit.js"
import { SessionState, type SessionStore } from "../policy/session.js"
import { renderEnvelope, stripStructured, wrapUntrusted } from "../untrusted/envelope.js"
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

/** Session binding: the caller must be the exact identity that opened the session. */
export function sessionMatchesIdentity(session: SessionState, identity: VerifiedIdentity): boolean {
  return session.subject === identity.subject && session.agentId === identity.clientId && session.actor === identity.actor
}

/**
 * The gateway. Only the tools in the agent's declared purpose are registered
 * for its session, and every call passes through the same sequence:
 *
 *   session binding -> scope check -> containment -> rate limit -> handler
 *   -> untrusted-output envelope -> audit
 *
 * Nothing in this sequence depends on the model's cooperation.
 */
export function registerManifestTools(server: McpServer, allowedTools: ReadonlySet<string>, deps: GatewayDeps): void {
  for (const tool of deps.manifest.tools) {
    if (!allowedTools.has(tool.name)) continue
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
        session.lastActivity = started

        // Advisory hints from the client about its own loop. They can only make
        // containment stricter (the counters never go down), so a lying client
        // gains nothing; an honest one gets earlier handoff.
        const meta = (extra._meta ?? {}) as { triggering_content_source?: unknown; iteration?: unknown; tokens_used?: unknown }
        const triggering = typeof meta.triggering_content_source === "string" ? meta.triggering_content_source : null
        if (typeof meta.iteration === "number" && meta.iteration > session.iterations) session.iterations = Math.floor(meta.iteration)
        if (typeof meta.tokens_used === "number" && meta.tokens_used > 0) session.tokensUsed += Math.floor(meta.tokens_used)
        const firstUse = !session.toolsUsed.has(tool.name)

        const base = (): Omit<ToolInvokedEvent, "decision" | "outcome"> => ({
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
        const contained = (reason: string, policy: ToolInvokedEvent["decision"]["policy"] = "contained") =>
          deps.audit({
            ...base(),
            decision: { iteration: session.iterations, triggering_content_source: triggering, policy, reason, human_approval: null },
            outcome: { status: "contained", latency_ms: Date.now() - started },
          })

        // 0. Session binding: the session was opened by one (subject, agent,
        //    workload). Any other identity presenting the session id is an
        //    attack signal, logged as such.
        if (!sessionMatchesIdentity(session, identity)) {
          contained("session_identity_mismatch")
          return errorResult("session_identity_mismatch", "token identity does not match session")
        }

        // 1. Scope: the token must carry the tool's required scope.
        if (!identity.scopes.includes(tool.required_scope)) {
          contained("insufficient_scope")
          return errorResult("insufficient_scope", `tool requires scope ${tool.required_scope}`)
        }

        // 2. Containment, before the call, every call. Any unexpected failure
        //    inside the check fails closed and is reported generically.
        try {
          check(session, tool, args, deps.budget, deps.flags)
        } catch (err) {
          if (err instanceof Contained) {
            contained(err.reason)
            return containedResult(err)
          }
          contained(err instanceof Error ? err.name : "unknown", "error")
          return errorResult("policy_error", "policy evaluation failed")
        }

        // 3. Rate limit per tool per delegating user.
        if (tool.rate_limit && !deps.rateLimiter.take(`${tool.name}:${identity.subject}`, tool.rate_limit)) {
          contained(tool.rate_limit, "rate_limited")
          return containedResult(new Contained("rate_limited", `rate limit ${tool.rate_limit} exceeded for ${tool.name}`))
        }

        // 4. Account for the call BEFORE running it, so a handler failure still
        //    consumed the approval and counted the mutation (fail closed).
        session.toolCalls += 1
        session.toolsUsed.add(tool.name)
        if (tool.touches_pii) deps.sessions.recordPiiAccess(session)
        let approvalKey: string | null = null
        if (tool.mutating && tool.reversible === false) {
          approvalKey = `${session.sessionId}/${SessionState.approvalKey(tool.name, args)}`
          session.consumeApproval(tool.name, args)
          deps.sessions.recordMutation(session)
        }

        try {
          const result = await handler(args, { identity, sessionId })
          let text = result.text
          let structured = result.structured

          // 5. Untrusted output is wrapped HERE, centrally, so no handler can
          //    forget. Structured fields are stripped too; the model sees them.
          if (tool.untrusted_output) {
            const env = wrapUntrusted(result.untrustedSource ?? `${tool.name}#result`, result.text)
            text = renderEnvelope(env)
            structured = {
              ...(stripStructured(structured ?? {}) as Record<string, unknown>),
              source: env.source,
              suspicious: env.suspicious,
              removed: env.removed,
            }
          }

          deps.audit({
            ...base(),
            decision: { iteration: session.iterations, triggering_content_source: triggering, policy: "allow", reason: null, human_approval: approvalKey },
            outcome: { status: "success", latency_ms: Date.now() - started },
          })
          const out: CallToolResult = { content: [{ type: "text", text }] }
          if (structured) out.structuredContent = structured
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

/** Validate approval arguments against the tool's own schema, so an operator cannot approve nonsense. */
export function validateApprovalArguments(tool: ToolDefinition, args: Record<string, unknown>): Record<string, unknown> | null {
  const parsed = z.object(parametersToZodShape(tool.parameters)).strict().safeParse(args)
  return parsed.success ? (parsed.data as Record<string, unknown>) : null
}
