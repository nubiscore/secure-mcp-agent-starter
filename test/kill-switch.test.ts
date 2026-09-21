import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"
import { FileFlagStore } from "../src/policy/kill-switch.js"

describe("file-backed kill switch", () => {
  const dir = mkdtempSync(join(tmpdir(), "kill-switch-"))

  it("fails CLOSED when the file is missing", () => {
    const store = new FileFlagStore(join(dir, "does-not-exist.json"))
    expect(store.isDisabled("agent-a", "1.0")).toBe(true)
    expect(() => store.read()).toThrow()
  })

  it("fails CLOSED when the file is malformed", () => {
    const path = join(dir, "bad.json")
    writeFileSync(path, "{ not json")
    expect(new FileFlagStore(path).isDisabled("agent-a", "1.0")).toBe(true)
    writeFileSync(path, JSON.stringify({ disabled_agents: "agent-a" }))
    // Wrong shape is treated as "not disabled" for that field, never as a crash.
    expect(new FileFlagStore(path).isDisabled("agent-a", "1.0")).toBe(false)
  })

  it("re-reads the file on every call so a flip takes effect immediately", () => {
    const path = join(dir, "flags.json")
    writeFileSync(path, JSON.stringify({ disabled_agents: [] }))
    const store = new FileFlagStore(path)
    expect(store.isDisabled("agent-a", "1.0")).toBe(false)
    writeFileSync(path, JSON.stringify({ disabled_agents: ["agent-a"] }))
    expect(store.isDisabled("agent-a", "1.0")).toBe(true)
    writeFileSync(path, JSON.stringify({ disable_all: true }))
    expect(store.isDisabled("agent-b", "9.9")).toBe(true)
  })
})
