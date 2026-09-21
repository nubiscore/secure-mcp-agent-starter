# Security policy

This repository is a reference implementation. It is meant to be forked and adapted, and it ships with a development-only token issuer that must never reach production.

## Reporting a vulnerability

If you find a weakness in the controls implemented here, a way to bypass the gateway, or an error in the security claims made in the README, please report it privately rather than opening a public issue.

Use the contact form at https://nubiscore.ca/consultation and mark the message as a security report.

Include the affected file, a description of the bypass, and reproduction steps if you have them. You will receive an acknowledgement within three business days.

## Scope

In scope:

- Bypasses of token verification, audience checking, session binding, purpose binding, containment, the approval gate, or rate limiting.
- Ways for tool output to escape the untrusted-content envelope unstripped.
- Audit events that omit or misattribute the identity or decision for a call.
- Weaknesses in the Kubernetes manifests that would allow egress or privilege the policies claim to deny.

Out of scope:

- The development issuer in `dev/issuer.ts` accepting unauthenticated mint requests. That is its documented purpose.
- In-memory state not surviving restarts or not being shared across replicas. Documented in the README.
- Prompt injection succeeding against a model despite the envelope. The envelope reduces probability; it is not claimed to be a complete defence.
