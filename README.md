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
| Two identities per call: delegating user and agent workload (`act` claim), both bound to the session | `src/auth/verify-token.ts` | Shared long-lived API keys with no attribution |
| Single-audience token check | `src/auth/verify-token.ts` | A token valid for several servers replayed against this one |
| Purpose-bound tool manifest: only the agent's declared tools are registered for its session | `tools/manifest.yaml`, `src/tools/registry.ts` | Tools an agent was never meant to have, even when its token has the scope |
| Whole-manifest hashing and pinning (tools and agent bindings) | `src/tools/manifest.ts` | Tool poisoning, rug pulls, and quietly widened purposes |
| Row-level authorization against the delegating user | `src/tools/handlers.ts` | An agent reading every user's data through one user's request |
| Session binding on every request, including SSE and session close | `src/server.ts`, `src/tools/registry.ts` | Driving or terminating one identity's session with another's token |
| Containment: tool-call cap, purpose binding, value ceiling, PII-then-egress chain break, mutation caps, all carried across sessions | `src/policy/containment.ts`, `src/policy/session.ts` | Runaway loops and read-then-exfiltrate sequences, including via a fresh session |
| Human-in-the-loop gate on the concrete, schema-valid parameters, single use, approved by a separate identity | `src/policy/session.ts`, `POST /admin/approvals` | Approving the agent's prose, or the agent approving itself |
| Per-tool, per-identity rate limits | `src/policy/rate-limit.ts` | Two hundred refunds an hour from an agent that normally does two |
| File-backed kill switch evaluated on every call, failing closed | `src/policy/kill-switch.ts` | Waiting for a deploy while an agent misbehaves at 02:00 |
| Untrusted-content envelope applied centrally by the gateway, with Unicode-aware carrier stripping | `src/untrusted/envelope.ts`, `src/tools/registry.ts` | Indirect prompt injection via zero-width, TAG-block, fullwidth, or HTML-comment carriers |
| Idle-session expiry and per-subject session cap | `src/server.ts` | A valid token exhausting memory by opening sessions |
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

The client walks through the controls step by step and prints what happened at each one. The server terminal prints one JSON audit event per tool call. `pnpm test` runs the same flow as an integration test, plus unit tests for each control.

### What the walkthrough shows

1. Discovery of the resource server through its protected resource metadata.
2. A delegated token for a user, acting through a declared agent, with this server as the audience.
3. The tool list, annotated with read-only, mutating, or destructive hints from the manifest. A second agent with the same scopes but a narrower purpose sees a shorter list.
4. Reading the user's own ticket succeeds. Reading another user's ticket with the same scope returns not found.
5. A knowledge base search returns a poisoned document. The hidden instruction is stripped, the result is wrapped in a provenance envelope, and the event is flagged as suspicious.
6. A comment is posted with a `triggering_content_source` so the audit trail records which document drove the decision.
7. A refund is requested. It is contained, not executed, and the response carries the concrete parameters and an approval key.
8. The agent tries to approve itself with the operator scope on its own token and is refused. An operator with a separate identity approves exactly those parameters.
9. The retry succeeds once.
10. A retry with different parameters is contained again. Approvals do not carry over. Then, because the session read PII earlier, an outbound notification is contained, and opening a fresh session does not reset that. Another user's token cannot terminate the session.
11. A token minted for a different resource server is rejected with an audience error.
12. A valid token for an agent that is not declared in the manifest is rejected.

Want to try to break it yourself? [TESTING.md](TESTING.md) is a hands-on checklist with the expected result for each attempt.

## How a call flows

```
agent ──bearer token──▶ /mcp
                          │
                          ├─ verify signature, issuer, single audience, expiry   (auth/verify-token.ts)
                          ├─ resolve session; user, agent, and workload must match (server.ts)
                          ├─ scope check against the tool's required_scope
                          ├─ containment: kill switch, caps, purpose, value ceiling,
                          │              PII-then-egress, approval gate          (policy/containment.ts)
                          ├─ rate limit per tool per user                        (policy/rate-limit.ts)
                          ├─ handler with row-level auth                         (tools/handlers.ts)
                          ├─ gateway wraps untrusted output, text and structured (untrusted/envelope.ts)
                          └─ emit audit event, allowed or not                    (audit/events.ts)
```

Nothing in that sequence depends on the model cooperating. That property is what makes it a control rather than a suggestion.

## The tool manifest

`tools/manifest.yaml` is the single file that declares the agent's entire capability surface. Review it like you would review an IAM policy.

```yaml
agents:
  agent-support-triage:
    tools: [get_ticket, search_kb, post_ticket_comment, notify_customer, issue_refund]

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

Parameter declarations become the tool's input schema, so a malformed argument never reaches the handler. Fields marked `redact: true` are blanked in audit events. `touches_pii` and `external_egress` feed the chain-breaking rule, which is keyed by (user, agent) and survives a new session. `untrusted_output` makes the gateway strip and wrap the result centrally, so a handler cannot forget. The `agents` block is purpose binding: only the tools listed for a `client_id` are registered for its session, whatever scopes its token carries.

`pnpm manifest:hash` prints the hash of the whole file, tool definitions and agent bindings alike. Set `MANIFEST_HASH_PIN` to that value and a changed manifest refuses to start. `deploy/k8s/manifest.yaml` must be an identical copy; `pnpm lint` fails if it drifts.

## Configuration

All configuration is environment variables. See `.env.example`.

| Variable | Purpose |
| --- | --- |
| `MCP_CANONICAL_URI` | This server's canonical identifier. Tokens must carry it in `aud`. |
| `OAUTH_ISSUER`, `OAUTH_JWKS_URL` | Your authorization server. The stub in `dev/issuer.ts` for local runs; Keycloak, Entra ID, Okta, Auth0, or your own in production. |
| `TOOL_MANIFEST` | Path to the manifest. |
| `MANIFEST_HASH_PIN` | Optional. Refuse to start if the manifest hash differs. |
| `KILL_SWITCH_FILE` | JSON file re-read on every call. Mount it from a ConfigMap in Kubernetes. Missing or malformed fails closed, and startup refuses to run without it. |
| `BUDGET_MAX_TOOL_CALLS` | Per-session cap on tool calls, counted by the gateway. |
| `BUDGET_MAX_MUTATIONS` | Irreversible actions per (user, agent) per hour, counted across sessions. |
| `BUDGET_MAX_ITERATIONS`, `BUDGET_MAX_TOKENS` | Caps on the agent's self-reported loop index and token spend, sent as `_meta.iteration` and `_meta.tokens_used` on tool calls. Advisory: a lying client gains nothing because the counters only ever go up, an honest one gets an earlier handoff. |

The server holds no long-lived secrets. It verifies tokens with the authorization server's public keys and nothing else.

## Deploying

```bash
kubectl apply -k deploy/k8s/gatekeeper   # cluster-scoped policy objects
kubectl apply -k deploy/k8s              # namespace, gateway, network policies, config
```

`deploy/k8s/` contains:

- a namespace under the `restricted` Pod Security level,
- a single-replica deployment that runs non-root with a read-only root filesystem, no capabilities, no service account token, and the manifest and kill switch mounted from a ConfigMap,
- a default-deny egress NetworkPolicy for pods labelled `app.kubernetes.io/component=agent-runtime`, allowing only DNS, the gateway, and an egress proxy, and a gateway policy that allows only DNS and the egress proxy, so neither the public internet nor the cloud instance metadata endpoint is reachable directly,
- an OPA Gatekeeper template and constraint that enforce `drop: [ALL]`, read-only root, non-root, and a component label the network policies actually select on.

Adjust the egress proxy namespace and labels in `networkpolicy.yaml` to your environment; without a proxy the gateway cannot fetch the authorization server's keys, which is the intended failure mode.

The kill switch is the ConfigMap. On-call flips it with `kubectl edit` and the next tool call from the disabled agent is contained. Exercise this in a game day before you need it. Note that `disabled_versions` keys on the version the MCP client reports about itself, which is useful for halting a bad rollout but is client-controlled; the per-agent and global switches key on the verified `client_id`.

## What this is not

- **Not a complete authorization server.** `dev/issuer.ts` mints tokens for anyone who asks. It exists so the starter runs on a laptop. Delete it from any real deployment.
- **Not multi-replica ready as-is.** Sessions, rate limits, approvals, and the cross-session ledger are in memory, which is why the deployment ships with one replica. Back them with Redis or your store of choice before scaling out. The interfaces are small and in `src/policy/`.
- **Not enforcing workload identity beyond binding.** The `act` claim is verified, bound to the session, and recorded in every audit event, but no policy here says "this workload may not call that tool". Add that in `check()` when you have a workload identity system to key it on.
- **Not a defence against prompt injection.** The envelope reduces the probability. The containment layer bounds the consequence. Neither is complete, and anyone selling you a complete one is overselling.
- **Not a product.** It is a reference you fork, keep the shape of, and replace the sample handlers in.

## Production checklist

Before this shape goes live with real tools behind it:

- [ ] Real authorization server issuing audience-restricted tokens with the `resource` parameter on both the authorization and token requests.
- [ ] Workload identity for the agent from SPIFFE/SPIRE, IRSA, GKE workload identity, or managed identity, carried in the `act` claim.
- [ ] Every handler enforces row-level authorization against `identity.subject`.
- [ ] `MANIFEST_HASH_PIN` set from the hash you reviewed and approved, and `deploy/k8s/manifest.yaml` in sync.
- [ ] Sessions, approvals, rate limits, and the ledger moved to a shared store before running more than one replica.
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
  policy/session.ts        per-session state, approvals, cross-session ledger
  policy/kill-switch.ts    file-backed flags, read on every call, fail closed
  policy/rate-limit.ts     sliding window per tool per identity
  untrusted/envelope.ts    strip hidden carriers, wrap with provenance
  audit/events.ts          one structured event per call
  server.ts                Express app: metadata, /mcp, /admin/approvals
dev/issuer.ts              development-only token issuer
examples/client.ts         the walkthrough
deploy/k8s/                kustomize base; deploy/k8s/gatekeeper for cluster-scoped policy
test/                      unit tests per control plus an end-to-end flow
```

## Background

The rationale for each control, the threat model, and a 90-day rollout order are in the article this repository accompanies: [Securing AI Agents in Production](https://nubiscore.ca/blog/securing-ai-agents). Related reading from the same series: [Building Production Agents on Amazon Bedrock](https://nubiscore.ca/blog/bedrock-agents) and [Securing Kubernetes with Network Policies and OPA Gatekeeper](https://nubiscore.ca/blog/securing-kubernetes).

Maintained by [NubisCore](https://nubiscore.ca). If you are putting agents into production and want a second pair of eyes on the identity and containment design, [get in touch](https://nubiscore.ca/consultation).

## License

Apache 2.0. See [LICENSE](LICENSE).
