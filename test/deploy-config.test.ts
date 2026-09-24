import { readFileSync } from "node:fs"
import { describe, expect, it } from "vitest"
import { parse, parseAllDocuments } from "yaml"
import { hashManifest, loadManifest } from "../src/tools/manifest.js"

/**
 * The Kubernetes base must be startable as shipped. The gateway refuses to run
 * if the manifest's `resource` differs from MCP_CANONICAL_URI, or if the
 * manifest differs from MANIFEST_HASH_PIN, so these are checked here rather
 * than discovered by a pod in CrashLoopBackOff.
 */
describe("deploy/k8s configuration", () => {
  const dev = loadManifest("tools/manifest.yaml")
  const deployed = loadManifest("deploy/k8s/manifest.yaml")

  const deploymentEnv = (): Record<string, string> => {
    const docs = parseAllDocuments(readFileSync("deploy/k8s/deployment.yaml", "utf8")).map((d) => d.toJS())
    const deployment = docs.find((d) => d?.kind === "Deployment")
    const env: Array<{ name: string; value?: string }> = deployment.spec.template.spec.containers[0].env
    return Object.fromEntries(env.filter((e) => e.value !== undefined).map((e) => [e.name, e.value as string]))
  }

  const pinnedHash = (): string | undefined => {
    const kustomization = parse(readFileSync("deploy/k8s/kustomization.yaml", "utf8"))
    const literals: string[] = kustomization.configMapGenerator[0].literals
    return literals.find((l) => l.startsWith("manifest_hash_pin="))?.slice("manifest_hash_pin=".length)
  }

  it("deploys the same tools and agent bindings as tools/manifest.yaml", () => {
    expect({ ...deployed, resource: undefined }).toEqual({ ...dev, resource: undefined })
  })

  it("sets the manifest resource to the deployment's canonical URI", () => {
    expect(deployed.resource).toBe(deploymentEnv().MCP_CANONICAL_URI)
  })

  it("pins the hash of the deployed manifest", () => {
    expect(pinnedHash()).toBe(hashManifest(deployed))
  })
})
