# secure-mcp-agent-starter

[![ci](https://github.com/nubiscore/secure-mcp-agent-starter/actions/workflows/ci.yml/badge.svg)](https://github.com/nubiscore/secure-mcp-agent-starter/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A runnable reference implementation of a production-hardened [Model Context Protocol](https://modelcontextprotocol.io) server and the gateway that sits between an AI agent and its tools.

It is the code behind NubisCore's article [Securing AI Agents in Production: Identity, MCP, and Least-Privilege Tool Access](https://nubiscore.ca/blog/securing-ai-agents). Every control the article describes is implemented here, tested, and demonstrated end to end by a sample client. Clone it, run three commands, and watch a poisoned document get stripped, an irreversible action get held for a human, a replayed token get rejected, and a kill switch take effect mid-session.

There is no LLM in the loop on purpose. The point is what the gateway does regardless of what a model asks for.

## What it implements

| Control | Where | What it closes |
| --- | --- | --- |
| OAuth 2.1 resource server with RFC 9728 protected resource metadata | `src/server.ts` | Clients guessing which authorization server to use |
| Audience-restricted token verification (RFC 8707 resource indicator) | `src/auth/verify-token.ts` | The confused deputy: a token for one server replayed against another |
| Two identities per call: delegating user and agent workload (`act` claim) | `src/auth/verify-token.ts` | Shared long-lived API keys with no attribution |
| Purpose-bound tool manifest, enforced not documented | `tools/manifest.yaml`, `src/tools/registry.ts` | Tools an agent was never meant to have, even when its token has the scope |
| Manifest hashing and pinning | `src/tools/manifest.ts` | Tool poisoning and rug pulls via changed descriptions or schemas |
| Row-level authorization against the delegating user | `src/tools/handlers.ts` | An agent reading every user's data through one user's request |
| Session binding | `src/tools/registry.ts` | Driving one user's session with another user's token |
| Containment: budgets, purpose binding, PII-then-egress chain break, mutation caps | `src/policy/containment.ts` | Runaway loops and read-then-exfiltrate sequences |
| Human-in-the-loop gate on the concrete parameters, single use | `src/policy/session.ts`, `POST /admin/approvals` | Approving the agent's prose instead of the actual action |
| Per-tool, per-identity rate limits | `src/policy/rate-limit.ts` | Two hundred refunds an hour from an agent that normally does two |
| File-backed kill switch evaluated on every call | `src/policy/kill-switch.ts` | Waiting for a deploy while an agent misbehaves at 02:00 |
| Untrusted-content envelope with hidden-carrier stripping | `src/untrusted/envelope.ts` | Indirect prompt injection via zero-width text and HTML comments |
| Structured audit event per call, with delegation chain and content provenance | `src/audit/events.ts` | "What did it do, under whose authority, and why?" |
| Hardened Kubernetes deployment: default-deny egress, no metadata endpoint, restricted PSA, Gatekeeper constraint | `deploy/k8s/` | Exfiltration routes and credential theft from the runtime |

## Quick start

Requires Node 20+ and pnpm.

```bash
pnpm install
cp dev/kill-switch.example.json dev/kill-switch.json

pnpm dev:issuer   # terminal 1: development-only token issuer on :3000
pnpm dev:server   # terminal 2: the MCP server on :3001
pnpm dev:client   # terminal 3: the walkthrough
```

The client walks through twelve steps and prints what happened at each one. The server terminal prints one JSON audit event per tool call. `pnpm test` runs the same flow as an integration test, plus unit tests for each control.

### What the walkthrough shows

1. Discovery of the resource server through its protected resource metadata.
2. A delegated token for a user, acting through a declared agent, with this server as the audience.
3. The tool list, annotated with read-only, mutating, or destructive hints from the manifest.
4. Reading the user's own ticket succeeds. Reading another user's ticket with the same scope returns not found.
5. A knowledge base search returns a poisoned document. The hidden instruction is stripped, the result is wrapped in a provenance envelope, and the event is flagged as suspicious.
6. A comment is posted with a `triggering_content_source` so the audit trail records which document drove the decision.
7. A refund is requested. It is contained, not executed, and the response carries the concrete parameters and an approval key.
8. An operator with a separate identity and the `agent:operate` scope approves exactly those parameters.
9. The retry succeeds once.
10. A retry with different parameters is contained again. Approvals do not carry over.
11. A token minted for a different resource server is rejected with an audience error.
12. A valid token for an agent that is not declared in the manifest is rejected.

## How a call flows

```
agent ──bearer token──▶ /mcp
                          │
                          ├─ verify signature, issuer, audience, expiry     (auth/verify-token.ts)
                          ├─ resolve session, check it belongs to this user (server.ts, tools/registry.ts)
                          ├─ scope check against the tool's required_scope
                          ├─ containment: kill switch, budgets, purpose,
                          │              PII-then-egress, approval gate      (policy/containment.ts)
                          ├─ rate limit per tool per user                   (policy/rate-limit.ts)
                          ├─ handler with row-level auth                    (tools/handlers.ts)
                          ├─ wrap untrusted output                          (untrusted/envelope.ts)
                          └─ emit audit event, allowed or not               (audit/events.ts)
```

Nothing in that sequence depends on the model cooperating. That property is what makes it a control rather than a suggestion.

## The tool manifest

`tools/manifest.yaml` is the single file that declares the agent's entire capability surface. Review it like you would review an IAM policy.

```yaml
agents:
  agent-support-triage:
    tools: [get_ticket, search_kb, post_ticket_comment, issue_refund]

tools:
  - name: issue_refund
    purpose: Issue a refund against a completed order
    required_scope: billing:refund
    mutating: true
    reversible: false
    authorization: delegated
    confirmation: human_in_the_loop   # required for irreversible tools; the loader rejects the manifest otherwise
    max_value_cents: 50000
    rate_limit: 5/hour
    parameters:
      order_id: { type: string, pattern: "^ORD-[0-9]{5}$" }
      amount_cents: { type: integer, min: 1, max: 50000 }
      reason: { type: string, max_length: 500 }
```

Parameter declarations become the tool's input schema, so a malformed argument never reaches the handler. Fields marked `redact: true` are blanked in audit events. `touches_pii` and `external_egress` feed the chain-breaking rule. The `agents` block is purpose binding: an agent may only call the tools listed for its `client_id`, whatever scopes its token carries.

The server prints the manifest hash at startup. Set `MANIFEST_HASH_PIN` to that value and a changed manifest refuses to start.

## Configuration

All configuration is environment variables. See `.env.example`.

| Variable | Purpose |
| --- | --- |
| `MCP_CANONICAL_URI` | This server's canonical identifier. Tokens must carry it in `aud`. |
| `OAUTH_ISSUER`, `OAUTH_JWKS_URL` | Your authorization server. The stub in `dev/issuer.ts` for local runs; Keycloak, Entra ID, Okta, Auth0, or your own in production. |
| `TOOL_MANIFEST` | Path to the manifest. |
| `MANIFEST_HASH_PIN` | Optional. Refuse to start if the manifest hash differs. |
| `KILL_SWITCH_FILE` | JSON file re-read on every call. Mount it from a ConfigMap in Kubernetes. |
| `BUDGET_*` | Per-session caps on iterations, tool calls, tokens, and irreversible mutations. |

The server holds no long-lived secrets. It verifies tokens with the authorization server's public keys and nothing else.

## Deploying

`deploy/k8s/` is a kustomize base with:

- a namespace under the `restricted` Pod Security level,
- a deployment that runs non-root with a read-only root filesystem, no capabilities, no service account token, and the manifest and kill switch mounted from a ConfigMap,
- a default-deny egress NetworkPolicy for agent runtimes and a gateway policy that excludes link-local addresses, so the cloud instance metadata endpoint is unreachable,
- an OPA Gatekeeper template and constraint that audit and enforce the same hardening.

The kill switch is the ConfigMap. On-call flips it with `kubectl edit` and the next tool call from the disabled agent is contained. Exercise this in a game day before you need it.

## What this is not

- **Not a complete authorization server.** `dev/issuer.ts` mints tokens for anyone who asks. It exists so the starter runs on a laptop. Delete it from any real deployment.
- **Not multi-replica ready as-is.** Sessions, rate limits, and approvals are in memory. Back them with Redis or your store of choice before running more than one replica. The interfaces are small and in `src/policy/`.
- **Not a defence against prompt injection.** The envelope reduces the probability. The containment layer bounds the consequence. Neither is complete, and anyone selling you a complete one is overselling.
- **Not a product.** It is a reference you fork, keep the shape of, and replace the sample handlers in.

## Production checklist

Before this shape goes live with real tools behind it:

- [ ] Real authorization server issuing audience-restricted tokens with the `resource` parameter on both the authorization and token requests.
- [ ] Workload identity for the agent from SPIFFE/SPIRE, IRSA, GKE workload identity, or managed identity, carried in the `act` claim.
- [ ] Every handler enforces row-level authorization against `identity.subject`.
- [ ] `MANIFEST_HASH_PIN` set from the hash you reviewed and approved.
- [ ] Sessions, approvals, and rate limits moved to a shared store.
- [ ] Audit events shipped to your SIEM with alerts on clustered authorization failures, first-time tool use, approval gates hit at unusual frequency, and manifest hash mismatches.
- [ ] Kill switch tested in a game day, by the people who will be on call.
- [ ] Egress proxy with an FQDN allowlist in front of any tool that reaches the internet.
- [ ] Code execution, if any, moved out of the container into gVisor, Firecracker, or a separate cluster.

## Project layout

```
src/
  auth/verify-token.ts     token verification, delegation chain
  tools/manifest.ts        manifest schema, loader, hash
  tools/registry.ts        the gateway: every tool call passes through here
  tools/handlers.ts        sample business logic with row-level auth
  policy/containment.ts    the check() evaluated before every call
  policy/session.ts        per-session state and parameter-bound approvals
  policy/kill-switch.ts    file-backed flags, read on every call
  policy/rate-limit.ts     sliding window per tool per identity
  untrusted/envelope.ts    strip hidden carriers, wrap with provenance
  audit/events.ts          one structured event per call
  server.ts                Express app: metadata, /mcp, /admin/approvals
dev/issuer.ts              development-only token issuer
examples/client.ts         the twelve-step walkthrough
deploy/k8s/                kustomize base with NetworkPolicy and Gatekeeper
test/                      unit tests per control plus an end-to-end flow
```

## Background

The rationale for each control, the threat model, and a 90-day rollout order are in the article this repository accompanies: [Securing AI Agents in Production](https://nubiscore.ca/blog/securing-ai-agents). Related reading from the same series: [Building Production Agents on Amazon Bedrock](https://nubiscore.ca/blog/bedrock-agents) and [Securing Kubernetes with Network Policies and OPA Gatekeeper](https://nubiscore.ca/blog/securing-kubernetes).

Maintained by [NubisCore](https://nubiscore.ca). If you are putting agents into production and want a second pair of eyes on the identity and containment design, [get in touch](https://nubiscore.ca/consultation).

## License

Apache 2.0. See [LICENSE](LICENSE).
