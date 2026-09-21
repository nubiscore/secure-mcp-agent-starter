import { readFileSync } from "node:fs"

/**
 * The kill switch is a file, re-read on every check. In Kubernetes it is a
 * ConfigMap mounted into the pod, so on-call can halt an agent, a version, or
 * everything with `kubectl edit` and no deploy. A flip takes effect on the
 * agent's NEXT tool call, mid-session.
 *
 * It fails CLOSED. If the file is missing, unreadable, or malformed, the
 * gateway does not know it is allowed to run, so it does not. Startup verifies
 * the file exists (see index.ts) so a misconfigured deploy is loud, not silent.
 *
 * Note on `disabled_versions`: the version is what the MCP client reports in
 * its initialize request. It is useful for halting a bad rollout, but it is
 * client-controlled and therefore not a security boundary. The per-agent and
 * global switches key on the verified `client_id` and are.
 *
 * Reading a small file per call is deliberate: correctness over the few
 * microseconds a cache would save. Swap in a feature-flag service if you have
 * one, but keep the "evaluated on every call" property.
 */
export type KillSwitchFlags = {
  disable_all?: boolean
  disabled_agents?: string[]
  disabled_versions?: string[]
}

export interface FlagStore {
  isDisabled(agentId: string, agentVersion: string): boolean
}

function evaluate(flags: KillSwitchFlags, agentId: string, agentVersion: string): boolean {
  if (flags.disable_all === true) return true
  if (Array.isArray(flags.disabled_agents) && flags.disabled_agents.includes(agentId)) return true
  if (Array.isArray(flags.disabled_versions) && flags.disabled_versions.includes(`${agentId}@${agentVersion}`)) return true
  return false
}

export class FileFlagStore implements FlagStore {
  constructor(private readonly path: string) {}

  /** Throws if the file is missing or malformed. Used at startup. */
  read(): KillSwitchFlags {
    const parsed: unknown = JSON.parse(readFileSync(this.path, "utf8"))
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`kill switch file ${this.path} must contain a JSON object`)
    }
    return parsed as KillSwitchFlags
  }

  isDisabled(agentId: string, agentVersion: string): boolean {
    try {
      return evaluate(this.read(), agentId, agentVersion)
    } catch {
      // Missing, unreadable, or malformed: fail closed.
      return true
    }
  }
}

export class MemoryFlagStore implements FlagStore {
  flags: KillSwitchFlags = {}
  isDisabled(agentId: string, agentVersion: string): boolean {
    return evaluate(this.flags, agentId, agentVersion)
  }
}
