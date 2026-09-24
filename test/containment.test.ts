import { describe, expect, it } from "vitest"
import { check, Contained, type SessionBudget } from "../src/policy/containment.js"
import { MemoryFlagStore } from "../src/policy/kill-switch.js"
import { SessionState, SessionStore } from "../src/policy/session.js"
import type { ToolDefinition } from "../src/tools/manifest.js"

const budget: SessionBudget = { maxIterations: 3, maxToolCalls: 3, maxTokens: 100, maxMutations: 1 }

const readTool: ToolDefinition = { name: "read", purpose: "Read a record safely", required_scope: "r", mutating: false, authorization: "delegated", parameters: {} }
const egressTool: ToolDefinition = { ...readTool, name: "notify", external_egress: true }
const refundTool: ToolDefinition = { ...readTool, name: "refund", mutating: true, reversible: false, confirmation: "human_in_the_loop", max_value_cents: 500 }

function session(allowed = ["read", "notify", "refund"]) {
  return new SessionState("s1", "agent-a", "1.0", "user_1", "spiffe://x/agent-a", new Set(allowed))
}

function reason(fn: () => void): string | null {
  try {
    fn()
    return null
  } catch (err) {
    if (err instanceof Contained) return err.reason
    throw err
  }
}

describe("containment", () => {
  it("allows an in-purpose read within budget", () => {
    expect(reason(() => check(session(), readTool, {}, budget, new MemoryFlagStore()))).toBeNull()
  })

  it("kill switch halts by agent, by version, or globally, and is evaluated per call", () => {
    const flags = new MemoryFlagStore()
    const s = session()
    expect(reason(() => check(s, readTool, {}, budget, flags))).toBeNull()
    flags.flags = { disabled_agents: ["agent-a"] }
    expect(reason(() => check(s, readTool, {}, budget, flags))).toBe("agent_disabled")
    flags.flags = { disabled_versions: ["agent-a@1.0"] }
    expect(reason(() => check(s, readTool, {}, budget, flags))).toBe("agent_disabled")
    flags.flags = { disabled_versions: ["agent-a@2.0"] }
    expect(reason(() => check(s, readTool, {}, budget, flags))).toBeNull()
    flags.flags = { disable_all: true }
    expect(reason(() => check(s, readTool, {}, budget, flags))).toBe("agent_disabled")
  })

  it("enforces tool-call, iteration, and token caps", () => {
    const s = session()
    s.toolCalls = 3
    expect(reason(() => check(s, readTool, {}, budget, new MemoryFlagStore()))).toBe("tool_call_cap")
    const t = session()
    t.iterations = 3
    expect(reason(() => check(t, readTool, {}, budget, new MemoryFlagStore()))).toBe("iteration_cap")
    const u = session()
    u.tokensUsed = 100
    expect(reason(() => check(u, readTool, {}, budget, new MemoryFlagStore()))).toBe("token_budget")
  })

  it("purpose binding: a tool outside the agent's declared set is refused even with scope", () => {
    expect(reason(() => check(session(["read"]), refundTool, {}, budget, new MemoryFlagStore()))).toBe("outside_purpose")
  })

  it("breaks the read-PII-then-exfiltrate chain", () => {
    const s = session()
    s.touchedPii = true
    expect(reason(() => check(s, egressTool, {}, budget, new MemoryFlagStore()))).toBe("egress_after_pii")
    expect(reason(() => check(s, readTool, {}, budget, new MemoryFlagStore()))).toBeNull()
  })

  it("gates irreversible actions on approval of the concrete parameters", () => {
    const s = session()
    const args = { order_id: "ORD-1", amount_cents: 100 }
    expect(reason(() => check(s, refundTool, args, budget, new MemoryFlagStore()))).toBe("human_approval_required")
    s.approve("refund", { amount_cents: 100, order_id: "ORD-1" }) // key order must not matter
    expect(reason(() => check(s, refundTool, args, budget, new MemoryFlagStore()))).toBeNull()
    expect(reason(() => check(s, refundTool, { ...args, amount_cents: 101 }, budget, new MemoryFlagStore()))).toBe("human_approval_required")
  })

  it("caps irreversible mutations", () => {
    const s = session()
    s.mutations = 1
    s.approve("refund", {})
    expect(reason(() => check(s, refundTool, {}, budget, new MemoryFlagStore()))).toBe("mutation_cap")
  })

  it("refuses an over-ceiling amount outright instead of offering it for approval", () => {
    const s = session()
    const args = { amount_cents: 501 }
    expect(reason(() => check(s, refundTool, args, budget, new MemoryFlagStore()))).toBe("value_ceiling")
  })
})

describe("session store ledger", () => {
  it("carries PII exposure and mutation counts into a new session for the same subject and agent", () => {
    const store = new SessionStore()
    const first = session()
    store.set(first)
    store.recordPiiAccess(first)
    store.recordMutation(first)
    expect(first.touchedPii).toBe(true)
    expect(first.mutations).toBe(1)

    const second = new SessionState("s2", "agent-a", "1.0", "user_1", "spiffe://x/agent-a", new Set(["notify"]))
    store.set(second)
    expect(second.touchedPii).toBe(true)
    expect(second.mutations).toBe(1)

    // A different user or agent starts clean.
    const other = new SessionState("s3", "agent-a", "1.0", "user_2", undefined, new Set(["notify"]))
    store.set(other)
    expect(other.touchedPii).toBe(false)
    expect(other.mutations).toBe(0)
  })

  it("syncs PII exposure and mutation counts into a session that was ALREADY open", () => {
    const store = new SessionStore()
    const early = session()
    const other = new SessionState("s2", "agent-a", "1.0", "user_1", "spiffe://x/agent-a", new Set(["notify"]))
    store.set(early)
    store.set(other)
    store.recordPiiAccess(other)
    store.recordMutation(other)
    expect(early.touchedPii).toBe(false)

    store.sync(early)
    expect(early.touchedPii).toBe(true)
    expect(early.mutations).toBe(1)
  })

  it("expires idle sessions and counts sessions per subject", () => {
    const store = new SessionStore()
    const a = session()
    a.lastActivity = 0
    store.set(a)
    store.set(new SessionState("s2", "agent-a", "1.0", "user_1", undefined, new Set()))
    expect(store.countForSubject("user_1")).toBe(2)
    expect(store.expireIdle(1000, 5000).map((s) => s.sessionId)).toEqual(["s1"])
    expect(store.countForSubject("user_1")).toBe(1)
  })
})
