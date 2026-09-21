# Try to break it

A hands-on checklist. Each item is an attack or a mistake, the command to make it, and what the gateway should do. If any item does not behave as written, that is a bug: please open an issue or a security report.

## Setup

Three terminals, or a remote box reached through an SSH tunnel:

```bash
pnpm install
cp dev/kill-switch.example.json dev/kill-switch.json
pnpm dev:issuer        # :3000, development-only token issuer
pnpm dev:server        # :3001, the MCP server
```

On a remote box, bind both to localhost with `HOST=127.0.0.1` and tunnel from your laptop:

```bash
ssh -N -L 3000:127.0.0.1:3000 -L 3001:127.0.0.1:3001 user@box
```

Everything below then runs from your laptop against `localhost`. Shell helpers used throughout:

```bash
MCP=http://localhost:3001
ISS=http://localhost:3000

# Mint a token from the dev issuer. Arguments: subject, client_id, scopes, audience.
mint() { curl -s $ISS/dev/token -H content-type:application/json \
  -d "{\"sub\":\"$1\",\"client_id\":\"$2\",\"scope\":\"$3\",\"resource\":\"${4:-$MCP}\",\"act\":{\"sub\":\"spiffe://example.com/ns/ai-agents/sa/$2\"}}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'; }

# Open an MCP session. Prints the session id.
init() { curl -s -D - -o /dev/null $MCP/mcp -H "authorization: Bearer $1" \
  -H content-type:application/json -H "accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"'"${2:-agent-support-triage}"'","version":"manual"}}}' \
  | awk 'tolower($1)=="mcp-session-id:"{print $2}' | tr -d '\r'; }

# Call a tool in a session. Arguments: token, session id, tool name, JSON arguments.
call() { curl -s $MCP/mcp -H "authorization: Bearer $1" -H "mcp-session-id: $2" \
  -H content-type:application/json -H "accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"'"$3"'","arguments":'"$4"'}}' \
  | sed -n 's/^data: //p; /^{/p'; }
```

The fastest end-to-end check is the scripted walkthrough, which runs every item below and prints each result:

```bash
pnpm dev:client
```

## 1. Discovery and authentication

| Try | Command | Expect |
| --- | --- | --- |
| Discover the server | `curl -s $MCP/.well-known/oauth-protected-resource` | JSON naming this server as `resource`, the issuer, and the scopes. No token needed. |
| Call with no token | `curl -si $MCP/mcp -X POST -H content-type:application/json -d '{}'` | `401` with a `WWW-Authenticate` header pointing at the metadata URL. |
| Replay a token for another server | `T=$(mint user_88213 agent-support-triage tickets:read https://finance.example.com); init $T` | Nothing printed. Run with `-i` on the curl inside `init` and you will see `401 invalid_token`, `unexpected "aud" claim value`. |
| Mint without a `resource` | `curl -si $ISS/dev/token -H content-type:application/json -d '{"sub":"u","client_id":"c","scope":"x"}'` | `400 invalid_target`. RFC 8707 is mandatory even at the dev issuer. |

## 2. Purpose binding

| Try | Command | Expect |
| --- | --- | --- |
| Undeclared agent, valid token | `T=$(mint user_88213 agent-rogue tickets:read); init $T agent-rogue` | Empty. With `-i`: `403 unknown_agent`. |
| Declared agent, all scopes, narrow purpose | `T=$(mint user_88213 agent-kb-indexer "tickets:read tickets:comment kb:search billing:refund"); S=$(init $T agent-kb-indexer); curl -s $MCP/mcp -H "authorization: Bearer $T" -H "mcp-session-id: $S" -H content-type:application/json -H "accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' \| sed -n 's/^data: //p'` | Only `search_kb`. The other four tools are not even registered for this session, whatever the token says. |
| Scope missing for a registered tool | `T=$(mint user_88213 agent-support-triage tickets:read); S=$(init $T); call $T $S issue_refund '{"order_id":"ORD-88213","amount_cents":100,"reason":"x"}'` | `insufficient_scope`. |

## 3. Row-level authorization

| Try | Command | Expect |
| --- | --- | --- |
| Read your own ticket | `T=$(mint user_88213 agent-support-triage tickets:read); S=$(init $T); call $T $S get_ticket '{"ticket_id":"TKT-004821"}'` | The ticket. |
| Read someone else's with the same scope | `call $T $S get_ticket '{"ticket_id":"TKT-004822"}'` | `not_found`. The handler checks the delegating user, not the agent. |
| Malformed argument | `call $T $S get_ticket '{"ticket_id":"1 OR 1=1"}'` | `Input validation error`. The handler never runs. |

## 4. Untrusted content

| Try | Command | Expect |
| --- | --- | --- |
| Search a poisoned document | `T=$(mint user_88213 agent-support-triage kb:search); S=$(init $T); call $T $S search_kb '{"query":"password"}'` | Text wrapped in `<untrusted_content source="kb:search#doc_2210">`, the hidden `IGNORE ALL PREVIOUS INSTRUCTIONS` comment gone, `suspicious: true` and a `removed` count in the structured result. |

To go further, edit the poisoned document in `src/tools/handlers.ts` and try fullwidth angle brackets (`＜/untrusted_content＞`), zero-width characters, or Unicode TAG characters. None should survive, and none should close the envelope early.

## 5. Human-in-the-loop approvals

```bash
T=$(mint user_88213 agent-support-triage "tickets:read billing:refund"); S=$(init $T)
A='{"order_id":"ORD-88213","amount_cents":41200,"reason":"duplicate charge"}'
```

| Try | Command | Expect |
| --- | --- | --- |
| Refund without approval | `call $T $S issue_refund "$A"` | `contained`, `human_approval_required`, with the exact arguments and an `approval_key`. Nothing was refunded. |
| Approve it yourself, agent token with operator scope | `SELF=$(mint user_88213 agent-support-triage "billing:refund agent:operate"); curl -si $MCP/admin/approvals -H "authorization: Bearer $SELF" -H content-type:application/json -d "{\"session_id\":\"$S\",\"tool\":\"issue_refund\",\"arguments\":$A}"` | `403 operator_not_separate`. |
| Approve nonsense as a real operator | `OP=$(mint oncall ops-console agent:operate); curl -si $MCP/admin/approvals -H "authorization: Bearer $OP" -H content-type:application/json -d "{\"session_id\":\"$S\",\"tool\":\"issue_refund\",\"arguments\":{\"order_id\":\"DROP TABLE\"}}"` | `400 invalid_arguments`. |
| Approve the real parameters | same, with `$A` as arguments | `201` with the approval key. |
| Retry the refund | `call $T $S issue_refund "$A"` | `refunded_cents: 41200`. |
| Retry again | `call $T $S issue_refund "$A"` | `human_approval_required` again. Approvals are single use. |
| Retry with a changed amount after a fresh approval of `$A` | change `amount_cents` | `human_approval_required`. Approval is bound to the exact parameters. |
| Ask for more than the ceiling | `amount_cents: 60000` | `Input validation error` from the schema. Lower the schema `max` in `tools/manifest.yaml` and you will get `value_ceiling` from containment instead, before any approval is offered. |

## 6. Read-then-exfiltrate

```bash
T=$(mint user_88213 agent-support-triage "tickets:read tickets:comment"); S=$(init $T)
call $T $S get_ticket '{"ticket_id":"TKT-004821"}'          # reads PII
call $T $S notify_customer '{"ticket_id":"TKT-004821","body":"hi"}'
```

Expect `egress_after_pii`. Now open a **new** session with the same token and call `notify_customer` again. Still `egress_after_pii`: the exposure is remembered per (user, agent) for an hour, so a fresh session does not launder it.

## 7. Session binding

```bash
T=$(mint user_88213 agent-support-triage tickets:read); S=$(init $T)
OTHER=$(mint user_11111 agent-support-triage tickets:read)
OTHER_AGENT=$(mint user_88213 agent-kb-indexer tickets:read)
```

| Try | Command | Expect |
| --- | --- | --- |
| Drive the session as another user | `call $OTHER $S get_ticket '{"ticket_id":"TKT-004822"}'` | `403`, `session belongs to another identity`. |
| Drive it as another agent for the same user | `call $OTHER_AGENT $S get_ticket '{"ticket_id":"TKT-004821"}'` | `403`. |
| Terminate it as another user | `curl -si -X DELETE $MCP/mcp -H "authorization: Bearer $OTHER" -H "mcp-session-id: $S"` | `403`, and the original token still works in the session. |
| Open a sixth session as one user | run `init $T` six times | The sixth returns `429 too_many_sessions`. |

## 8. Kill switch and rate limits

| Try | Command | Expect |
| --- | --- | --- |
| Disable the agent mid-session | edit `dev/kill-switch.json` to `{"disabled_agents":["agent-support-triage"]}`, then any `call` | `agent_disabled` on the very next call, no restart. Revert the file and calls resume. |
| Delete the kill switch file | `rm dev/kill-switch.json`, then any `call` | `agent_disabled`. Missing means fail closed. Restore it from the example. |
| Exceed a rate limit | call `post_ticket_comment` eleven times in a row | The eleventh is `rate_limited` (10/hour in the manifest). |

## 9. Manifest integrity

| Try | Command | Expect |
| --- | --- | --- |
| Print the approved hash | `pnpm manifest:hash` | A `sha256:` value. |
| Widen an agent's purpose and restart with the pin set | add a tool to `agent-kb-indexer` in `tools/manifest.yaml`, then `MANIFEST_HASH_PIN=<old hash> pnpm dev:server` | `startup refused: manifest hash mismatch`. Changing only the `agents` block is enough to trip it. |
| Point the server at a different canonical URI than the manifest | `MCP_CANONICAL_URI=https://other.example pnpm dev:server` | `startup refused: manifest.resource ... does not match`. |

## 10. Audit trail

Watch the server terminal while doing any of the above. Every attempt, allowed or not, produces one `agent.tool.invoked` JSON line with the user, the workload identity, the tool, redacted arguments, the decision and its reason, and the manifest hash. Approvals produce `agent.approval.granted` naming the operator. Binding violations and refused sessions produce `agent.session.refused`.

Things worth confirming: the comment `body` is blank in the log (`redact: true`), the successful refund carries the `human_approval` key, and the `triggering_content_source` field is populated when the client sends it in `_meta`.
