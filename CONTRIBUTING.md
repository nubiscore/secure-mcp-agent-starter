# Contributing

Thanks for looking at this. The bar for changes is: does it make the reference clearer or the controls stronger, without turning the repository into a product.

## Ground rules

- Every control has a test. A change to `src/policy/`, `src/auth/`, or `src/tools/registry.ts` needs a test that fails without it.
- The manifest stays the single source of truth for what an agent can do. Do not add a code path that grants a capability the manifest does not declare.
- Keep the sample handlers boring. They exist to show row-level authorization, not to be a ticketing system.
- No new runtime dependencies without a reason in the PR description.

## Workflow

```bash
pnpm install
pnpm lint      # eslint + tsc
pnpm test      # vitest, including the end-to-end flow
pnpm dev:issuer && pnpm dev:server && pnpm dev:client   # in three terminals
```

CI runs lint, tests, build, and a container build on every pull request.

## Changing the manifest

If you change `tools/manifest.yaml`, the hash printed at startup changes. Update any pinned value in `deploy/k8s/kustomization.yaml` and mention the new hash in the PR so reviewers can confirm it.
