import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import { parse } from "yaml"
import { z } from "zod"

/**
 * Schema for tools/manifest.yaml. Everything the gateway enforces is declared
 * here, so a reviewer can audit the agent's entire capability surface from a
 * single file, and the hash of that file is the thing you pin.
 */
const ParameterSchema = z.object({
  type: z.enum(["string", "integer", "number", "boolean"]),
  description: z.string().optional(),
  pattern: z.string().optional(),
  max_length: z.number().int().positive().optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  /** Redacted in audit events (free text that may contain PII). */
  redact: z.boolean().optional(),
})

const RateLimitSchema = z
  .string()
  .regex(/^\d+\/(minute|hour|day)$/, "rate_limit must look like 10/hour")

export const ToolSchema = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9_]*$/),
    purpose: z.string().min(10),
    required_scope: z.string().min(1),
    mutating: z.boolean(),
    reversible: z.boolean().optional(),
    authorization: z.enum(["delegated", "workload"]),
    confirmation: z.enum(["human_in_the_loop"]).optional(),
    rate_limit: RateLimitSchema.optional(),
    max_value_cents: z.number().int().positive().optional(),
    touches_pii: z.boolean().optional(),
    external_egress: z.boolean().optional(),
    untrusted_output: z.boolean().optional(),
    parameters: z.record(z.string(), ParameterSchema).default({}),
  })
  .superRefine((tool, ctx) => {
    if (tool.mutating && tool.reversible === undefined) {
      ctx.addIssue({ code: "custom", message: `${tool.name}: mutating tools must declare reversible: true|false` })
    }
    if (tool.mutating && tool.reversible === false && tool.confirmation !== "human_in_the_loop") {
      ctx.addIssue({ code: "custom", message: `${tool.name}: irreversible tools must set confirmation: human_in_the_loop` })
    }
  })

export const ManifestSchema = z.object({
  resource: z.string().url(),
  agents: z.record(z.string(), z.object({ tools: z.array(z.string()).min(1) })),
  tools: z.array(ToolSchema).min(1),
})

export type ToolDefinition = z.infer<typeof ToolSchema>
export type ParameterDefinition = z.infer<typeof ParameterSchema>
export type Manifest = z.infer<typeof ManifestSchema>

export function parseManifest(text: string): Manifest {
  const manifest = ManifestSchema.parse(parse(text))
  const names = new Set(manifest.tools.map((t) => t.name))
  if (names.size !== manifest.tools.length) throw new Error("duplicate tool names in manifest")
  for (const [agent, cfg] of Object.entries(manifest.agents)) {
    for (const t of cfg.tools) {
      if (!names.has(t)) throw new Error(`agent ${agent} references unknown tool ${t}`)
    }
  }
  return manifest
}

export function loadManifest(path: string): Manifest {
  return parseManifest(readFileSync(path, "utf8"))
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((k) => [k, canonicalize((value as Record<string, unknown>)[k])]),
    )
  }
  return value
}

/**
 * Stable hash of the WHOLE manifest: tool definitions (name, description,
 * parameter schema) and the agent purpose bindings. Record it at approval
 * time, verify it on every start, log it on every event. A changed hash is
 * how you detect a rug pull, and a widened purpose is a rug pull too.
 */
export function hashManifest(manifest: Manifest): string {
  const digest = createHash("sha256").update(JSON.stringify(canonicalize(manifest))).digest("hex")
  return `sha256:${digest}`
}

/** Startup guard: refuse to run a manifest other than the one that was approved. */
export function assertManifestPinned(manifest: Manifest, pin: string | undefined): string {
  const hash = hashManifest(manifest)
  if (pin && pin !== hash) {
    throw new Error(`manifest hash mismatch: pinned ${pin}, loaded ${hash}`)
  }
  return hash
}

export function parseRateLimit(spec: string): { limit: number; windowMs: number } {
  const [count, unit] = spec.split("/") as [string, "minute" | "hour" | "day"]
  const windowMs = { minute: 60_000, hour: 3_600_000, day: 86_400_000 }[unit]
  return { limit: Number.parseInt(count, 10), windowMs }
}

/** Convert manifest parameter declarations into a zod shape for the MCP SDK. */
export function parametersToZodShape(params: Record<string, ParameterDefinition>): Record<string, z.ZodTypeAny> {
  const shape: Record<string, z.ZodTypeAny> = {}
  for (const [name, p] of Object.entries(params)) {
    let schema: z.ZodTypeAny
    switch (p.type) {
      case "string": {
        let s = z.string()
        if (p.pattern) s = s.regex(new RegExp(p.pattern))
        if (p.max_length) s = s.max(p.max_length)
        schema = s
        break
      }
      case "integer":
      case "number": {
        let n = p.type === "integer" ? z.number().int() : z.number()
        if (p.min !== undefined) n = n.min(p.min)
        if (p.max !== undefined) n = n.max(p.max)
        schema = n
        break
      }
      case "boolean":
        schema = z.boolean()
        break
    }
    shape[name] = p.description ? schema.describe(p.description) : schema
  }
  return shape
}
