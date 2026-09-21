import { readFileSync } from "node:fs"

/**
 * The kill switch is a file, re-read on every check. In Kubernetes it is a
 * ConfigMap mounted into the pod, so on-call can halt an agent, a version, or
 * everything with `kubectl edit` and no deploy. A flip takes effect on the
 * agent's NEXT tool call, mid-session.
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

export class FileFlagStore implements FlagStore {
  constructor(private readonly path: string) {}

  read(): KillSwitchFlags {
    try {
      return JSON.parse(readFileSync(this.path, "utf8")) as KillSwitchFlags
    } catch (err) {
      // A missing file means "no flags set". Any other failure fails CLOSED:
      // if we cannot read the kill switch we do not know we are allowed to run.
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return {}
      return { disable_all: true }
    }
  }

  isDisabled(agentId: string, agentVersion: string): boolean {
    const flags = this.read()
    if (flags.disable_all) return true
    if (flags.disabled_agents?.includes(agentId)) return true
    if (flags.disabled_versions?.includes(`${agentId}@${agentVersion}`)) return true
    return false
  }
}

export class MemoryFlagStore implements FlagStore {
  flags: KillSwitchFlags = {}
  isDisabled(agentId: string, agentVersion: string): boolean {
    const f = this.flags
    return Boolean(f.disable_all || f.disabled_agents?.includes(agentId) || f.disabled_versions?.includes(`${agentId}@${agentVersion}`))
  }
}
