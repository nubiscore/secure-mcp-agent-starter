import type { ToolDefinition } from "../tools/manifest.js"
import type { FlagStore } from "./kill-switch.js"
import type { SessionState } from "./session.js"

export type SessionBudget = {
  maxIterations: number
  maxToolCalls: number
  maxTokens: number
  /** Irreversible actions per session. */
  maxMutations: number
}

export type ContainmentReason =
  | "agent_disabled"
  | "iteration_cap"
  | "tool_call_cap"
  | "token_budget"
  | "outside_purpose"
  | "egress_after_pii"
  | "mutation_cap"
  | "human_approval_required"
  | "rate_limited"

/** Raised to halt the loop and escalate to a human. */
export class Contained extends Error {
  constructor(
    readonly reason: ContainmentReason,
    message: string,
    readonly detail: Record<string, unknown> = {},
  ) {
    super(message)
    this.name = "Contained"
  }
}

/**
 * Evaluated in the tool-invocation path, before EVERY call, with no
 * dependency on the model cooperating. That property is what makes this a
 * control rather than a suggestion.
 */
export function check(
  session: SessionState,
  tool: ToolDefinition,
  args: Record<string, unknown>,
  budget: SessionBudget,
  flags: FlagStore,
): void {
  // 1. Global and per-agent kill switch, evaluated on every call so a flip
  //    takes effect mid-session, not at the next deploy.
  if (flags.isDisabled(session.agentId, session.agentVersion)) {
    throw new Contained("agent_disabled", "agent disabled by kill switch")
  }

  // 2. Budgets. When a cap is hit, fail into a human handoff, never degrade silently.
  if (session.iterations >= budget.maxIterations) {
    throw new Contained("iteration_cap", "iteration cap reached", { cap: budget.maxIterations })
  }
  if (session.toolCalls >= budget.maxToolCalls) {
    throw new Contained("tool_call_cap", "tool call cap reached", { cap: budget.maxToolCalls })
  }
  if (session.tokensUsed >= budget.maxTokens) {
    throw new Contained("token_budget", "token budget exhausted", { cap: budget.maxTokens })
  }

  // 3. Purpose binding: the tool must be in this agent's declared set,
  //    regardless of which scopes the token carries.
  if (!session.allowedTools.has(tool.name)) {
    throw new Contained("outside_purpose", `tool ${tool.name} outside declared purpose for ${session.agentId}`)
  }

  // 4. Break parasitic chains: no external egress after reading PII in this session.
  if (tool.external_egress && session.touchedPii) {
    throw new Contained("egress_after_pii", "egress blocked after PII access in session")
  }

  // 5. Irreversible actions are gated, always, on the concrete parameters.
  if (tool.mutating && tool.reversible === false) {
    if (session.mutations >= budget.maxMutations) {
      throw new Contained("mutation_cap", "mutation cap reached", { cap: budget.maxMutations })
    }
    if (!session.hasHumanApproval(tool.name, args)) {
      throw new Contained("human_approval_required", "human approval required", {
        tool: tool.name,
        arguments: args,
        approval_key: approvalKeyFor(session, tool.name, args),
      })
    }
  }

  // 6. Value ceiling on financial tools, enforced here even though the schema also bounds it.
  if (tool.max_value_cents !== undefined && typeof args.amount_cents === "number" && args.amount_cents > tool.max_value_cents) {
    throw new Contained("outside_purpose", `amount exceeds max_value_cents for ${tool.name}`, { max_value_cents: tool.max_value_cents })
  }
}

function approvalKeyFor(session: SessionState, toolName: string, args: Record<string, unknown>): string {
  // Exposed so an operator can approve exactly this call and nothing else.
  return `${session.sessionId}/${(session.constructor as typeof SessionState).approvalKey(toolName, args)}`
}
