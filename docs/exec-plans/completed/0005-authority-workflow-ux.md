# Completed plan: Authority workflow UX

## Goal

Make `ctxa` feel better than a raw credential proxy for local agent users.

The current proxy path can safely broker HTTP and HTTPS credentials, but users
still need to hand-edit profile resources and inspect raw audit output. This
pass turns the proxy into an agent authority workflow:

```text
setup agent profile -> run agent -> denied request becomes proposal -> human applies proposal -> agent reruns -> signed receipt is inspectable
```

## Positioning

This pass should reinforce the product distinction:

- `ctxa` is not only a secrets vault.
- `ctxa` is a local authority layer that gives agents scoped capabilities,
  redacted proposals, verifiable receipts, and runtime-agnostic instructions.

## Scope for this implementation

### One-command setup

Add:

```text
ctxa setup runtime <codex|claude-code|openclaw|generic> --profile <id> [--agent <id>]
```

Behavior:

- Ensure local state exists.
- Create the profile when missing.
- Preserve existing profile resources and environment values when the profile
  already exists.
- Install the runtime-agnostic `ctx authority` skill at
  `$CTXA_HOME/skills/ctx-authority/SKILL.md` so agents can be pointed at it
  without copying repo internals.
- Rerunning setup is idempotent: it updates the installed skill content but does
  not duplicate profiles or mutate existing profile resources.
- Run local diagnostics that do not resolve secret values.
- Print concise next commands:
  - `ctxa profile add-https ...`
  - `ctxa run --profile <id> -- <runtime command>`
  - `ctxa proposals list`
  - `ctxa receipts list`

The setup command must not create secrets, print secrets, depend on a hosted
service, or require network access.

### Proposal-to-policy workflow

Existing denied authenticated proxy requests create redacted proposal events.
Make those proposals actionable:

```text
ctxa proposals list [--all] [--limit <n>]
ctxa proposals show <id>
ctxa proposals apply <id> --secret-ref <ref> [--resource-id <id>] [--path-prefix <prefix>] [--allow-method <method>...]
ctxa proposals dismiss <id> [--reason <text>]
```

Behavior:

- Proposal records include `scheme` for HTTP and HTTPS resources.
- `list` shows open proposals by default. `--all` includes applied and
  dismissed proposals. Results are newest-first by audit event order.
- `show` prints the redacted proposal JSON and status.
- `apply` creates a profile HTTP resource using the proposal host, scheme, and
  selected methods/path prefix.
- `apply` creates a new resource by default. It fails on resource-id collision
  unless `--replace` is explicit.
- `apply` requires a human-supplied `--secret-ref`; proposals never contain
  secret references.
- `apply` defaults to the proposed method and proposed path as the narrowest
  safe path prefix. Path-prefix matching remains segment-boundary matching, so
  `/foo` can authorize `/foo/bar` but not `/foobar`.
- `dismiss` records an immutable audit event.
- All proposal state is derived from immutable audit events.
- Applying an already applied proposal is idempotent and must not create a
  duplicate resource.
- Dismissing an already dismissed proposal is idempotent.
- Applied and dismissed are terminal statuses; default `list` shows only open
  proposals.
- `--reason` on dismissal is optional human-supplied text. It is length capped,
  control-character sanitized, and omitted from default proposal list output.
- Proposal/apply canonicalization uses the recorded scheme, canonical host and
  port, uppercase method, and normalized path. `CONNECT` is never surfaced as an
  allowed method; proposal methods are the decrypted HTTP request methods.

### Receipt UX

Add:

```text
ctxa receipts list [--limit <n>]
ctxa receipts show <id>
ctxa receipts verify <file>
```

Behavior:

- `list` includes receipts emitted by both explicit action execution and profile
  proxy execution.
- `list` prints receipt id, action, resource, agent, status, and issued time.
- `show` prints the complete receipt JSON from local audit storage.
- Missing receipt ids return a non-zero error.
- Receipt list ordering is newest-first by audit event order.
- `verify` behavior remains unchanged.

### Compatibility and docs

- Add docs for the setup/proposal/receipt loop.
- Update the runtime-agnostic skill so agents know to use proposals instead of
  asking for raw credentials after a denial.
- Extend CLI smoke tests to cover setup, proposal listing, and receipt listing.
- Keep all tests closed-system with fake backends and loopback servers.

## Security constraints

- Denied unauthenticated requests must not create proposals.
- Proposal records must not include raw query strings, bodies, caller auth
  headers, or secret references.
- Proposal application must require explicit human selection of a secret
  reference.
- Proposal application must not resolve or validate the selected secret
  reference.
- Unauthenticated and malformed denied requests must not create proposals.
- Setup output must not include secret values.
- Receipt list/show must not expose raw secrets.
- Existing proxy behavior must remain fail closed.

## Acceptance criteria

- `ctxa setup runtime codex --profile codex` creates local state, creates or
  preserves the profile, installs the skill, runs diagnostics, and prints next
  commands.
- An authenticated denied HTTPS request records a proposal with a scheme.
- Unauthenticated and malformed denied proxy requests do not create proposals.
- `ctxa proposals list` shows the open proposal without raw query or body data.
- `ctxa proposals apply <id> --secret-ref github` creates a matching profile
  resource and records `proxy_request_proposal_applied`.
- `ctxa proposals apply <id> --secret-ref github` does not resolve `github`.
- Applying a proposal twice does not create duplicate resources.
- Applied proposals are hidden from default `list` and visible with `--all`.
- `ctxa proposals dismiss <id>` records dismissal and hides the proposal from
  default `list`.
- `ctxa receipts list` shows proxy receipts and action receipts.
- `ctxa receipts show <id>` prints a stored receipt that verifies.
- A closed-loop integration test covers denied HTTPS request -> proposal ->
  apply -> rerun allowed HTTPS request -> receipt list/show -> receipt verify.
- Full gate passes:

```text
cargo fmt --all -- --check
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
bazel test //:full_suite
```
