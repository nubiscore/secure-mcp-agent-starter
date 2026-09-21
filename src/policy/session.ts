import { createHash } from "node:crypto"

/**
 * Per-session containment state. One instance per MCP session, bound to the
 * identity that initialised the session. Lives in the gateway, not the model.
 */
export class SessionState {
  iterations = 0
  toolCalls = 0
  tokensUsed = 0
  mutations = 0
  touchedPii = false
  /** Tools this agent has already used in this session; first use is a signal. */
  readonly toolsUsed = new Set<string>()
  private readonly approvals = new Set<string>()

  constructor(
    readonly sessionId: string,
    readonly agentId: string,
    readonly agentVersion: string,
    /** Subject the session was initialised for. Later requests must match. */
    readonly subject: string,
    readonly allowedTools: ReadonlySet<string>,
  ) {}

  static approvalKey(toolName: string, args: Record<string, unknown>): string {
    const canonical = JSON.stringify(Object.fromEntries(Object.entries(args).sort(([a], [b]) => a.localeCompare(b))))
    return `${toolName}:${createHash("sha256").update(canonical).digest("hex")}`
  }

  /**
   * Approval is for the CONCRETE parameters, never the agent's description of
   * what it intends. A human approving prose is approving the wrong thing.
   */
  approve(toolName: string, args: Record<string, unknown>): string {
    const key = SessionState.approvalKey(toolName, args)
    this.approvals.add(key)
    return key
  }

  hasHumanApproval(toolName: string, args: Record<string, unknown>): boolean {
    return this.approvals.has(SessionState.approvalKey(toolName, args))
  }

  /** Approvals are single-use. */
  consumeApproval(toolName: string, args: Record<string, unknown>): void {
    this.approvals.delete(SessionState.approvalKey(toolName, args))
  }
}

export class SessionStore {
  private readonly sessions = new Map<string, SessionState>()
  get(id: string): SessionState | undefined {
    return this.sessions.get(id)
  }
  set(state: SessionState): void {
    this.sessions.set(state.sessionId, state)
  }
  delete(id: string): void {
    this.sessions.delete(id)
  }
}
