import { parseRateLimit } from "../tools/manifest.js"

/**
 * Sliding-window rate limiter keyed by (tool, identity). In-memory, so it is
 * per replica. For a multi-replica deployment back it with Redis; the
 * interface is the only thing the gateway depends on.
 */
export interface RateLimiter {
  /** Returns true if the call is allowed and records it. */
  take(key: string, spec: string): boolean
}

export class MemoryRateLimiter implements RateLimiter {
  private readonly hits = new Map<string, number[]>()
  constructor(private readonly now: () => number = Date.now) {}

  take(key: string, spec: string): boolean {
    const { limit, windowMs } = parseRateLimit(spec)
    const t = this.now()
    const recent = (this.hits.get(key) ?? []).filter((ts) => t - ts < windowMs)
    if (recent.length >= limit) {
      this.hits.set(key, recent)
      return false
    }
    recent.push(t)
    this.hits.set(key, recent)
    return true
  }
}
