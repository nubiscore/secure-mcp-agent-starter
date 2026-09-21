import { describe, expect, it } from "vitest"
import { MemoryRateLimiter } from "../src/policy/rate-limit.js"

describe("rate limiter", () => {
  it("allows up to the limit in the window, then refuses, then recovers", () => {
    let now = 0
    const rl = new MemoryRateLimiter(() => now)
    expect(rl.take("refund:user_1", "2/minute")).toBe(true)
    expect(rl.take("refund:user_1", "2/minute")).toBe(true)
    expect(rl.take("refund:user_1", "2/minute")).toBe(false)
    expect(rl.take("refund:user_2", "2/minute")).toBe(true) // keyed per identity
    now = 60_001
    expect(rl.take("refund:user_1", "2/minute")).toBe(true)
  })
})
