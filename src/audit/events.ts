import type { ToolDefinition } from "../tools/manifest.js"

/**
 * One structured event per tool invocation, emitted whether the call was
 * allowed, contained, or failed. Ship these to your SIEM alongside application
 * logs and alert on: clustered authorization failures, tool-call rates outside
 * baseline, manifest hash mismatches, first-time tool use, and approval gates
 * hit at unusual frequency.
 */
export type AuditEvent = {
  event: "agent.tool.invoked"
  timestamp: string
  trace_id: string
  session_id: string
  agent: { id: string; version: string }
  identity: {
    workload: string | undefined
    on_behalf_of: string
    token_audience: string
    scopes: string[]
  }
  tool: {
    name: string
    server: string
    manifest_hash: string
    arguments_redacted: Record<string, unknown>
    mutating: boolean
    reversible: boolean | undefined
    first_use_in_session: boolean
  }
  decision: {
    iteration: number
    /** Provenance of the content that preceded this call, if the client reported it. */
    triggering_content_source: string | null
    policy: "allow" | "contained" | "rate_limited" | "error"
    reason: string | null
    human_approval: string | null
  }
  outcome: { status: "success" | "contained" | "error"; latency_ms: number }
}

export type AuditSink = (event: AuditEvent) => void

/** Default sink: one JSON line per event on stdout, ready for a log shipper. */
export const stdoutSink: AuditSink = (event) => {
  process.stdout.write(JSON.stringify(event) + "\n")
}

/**
 * Arguments are logged, but fields flagged `redact: true` in the manifest are
 * blanked. You want the ticket id in the log; you do not want the comment body.
 */
export function redactArguments(tool: ToolDefinition, args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(args)) {
    out[k] = tool.parameters[k]?.redact ? "" : v
  }
  return out
}
