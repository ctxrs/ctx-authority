# Completed plan: attenuable grants

## Outcome

The repository includes first-class local HTTP grants that can be delegated into
narrower child grants.

The core invariant is:

```text
child grant <= parent grant
```

This lets a profile that holds a broad grant mint narrower grants for another
profile without copying the underlying secret reference into the child grant.

## Product behavior

The implementation is local-first and CLI-first:

```bash
ctxa grants create-https \
  --id github-root \
  --profile main-agent \
  --host api.github.com \
  --secret-ref op://example-vault/github-token/token \
  --allow-method GET \
  --path-prefix /repos/acme/app \
  --delegable \
  --max-depth 2

ctxa grants delegate \
  --from github-root \
  --id github-issues \
  --profile worker-agent \
  --allow-method GET \
  --path-prefix /repos/acme/app/issues
```

`ctxa run --profile worker-agent -- <agent>` allows requests covered by
`github-issues`. The broker resolves the root secret reference internally and
writes receipts that include grant-chain metadata in redacted form.

## Implemented scope

### Grant config

`config.yaml` supports a global `grants` collection. Each HTTP grant includes:

- stable grant id
- optional parent grant id
- profile id that holds the grant
- subject string derived from the profile agent id, or the profile id when no
  profile agent is configured
- HTTP scheme, host, methods, and path prefixes
- root-only secret reference
- delegation settings: `allowed: bool` and `remaining_depth: u8`

Root grants have no parent and must have a secret reference. Child grants have a
parent and must not store a secret reference.

Stored grant subjects must not drift from the profile that holds the grant. On
config load, the stored subject must match the current profile agent id, or the
profile id when no profile agent is configured.

### Delegation rules

Delegation must be mechanically validated:

- parent grant exists
- parent allows delegation
- parent remaining depth is greater than zero
- child `delegation.remaining_depth` is less than parent
  `delegation.remaining_depth`
- child `delegation.allowed = false` requires child
  `delegation.remaining_depth = 0`
- child `delegation.allowed = true` requires child
  `delegation.remaining_depth > 0`
- child scheme and canonical host match the parent
- child methods are uppercase, deduplicated, and a subset of parent methods
- every child path prefix is equal to, or inside, a parent path prefix
- child grants never copy or store the root secret reference
- referenced profiles exist
- cycles are rejected

### Proxy integration

Profile proxy matching checks both:

- legacy profile `http_resources`
- global grants held by the profile

When a grant matches, the broker resolves the root secret reference by walking
the parent chain. The agent never receives the root secret value. Receipts use
the matched grant id as the resource id.

Grant-backed receipts use a grant policy hash envelope that binds:

- holder profile id and subject
- matched grant id
- full chain ids from root to matched grant
- scheme and canonical host
- methods and path prefixes for each grant in the chain
- delegation settings for each grant in the chain
- root secret reference hash

The receipt execution result may include grant ids and a grant-chain hash, but
must not include raw secret references.

### CLI

The CLI includes:

```bash
ctxa grants list [--profile <id>]
ctxa grants show <id>
ctxa grants create-http ...
ctxa grants create-https ...
ctxa grants delegate ...
```

`show` does not print raw secret references. It prints whether the grant has a
root secret reference and includes redacted chain metadata.

Grant mutation commands modify local config. They enforce grant attenuation, but
they are not an isolation boundary against a local process that already has
write access to `CTXA_HOME`. Local operators may delegate from any configured
delegable parent grant. Strong holder identity for config mutation requires a
separate runtime or daemon boundary.

Grant mutation commands record redacted audit events:

- `grant_created`
- `grant_delegated`

These events may include grant ids, profile ids, subject strings, capability
dimensions, delegation settings, parent ids, and whether a root secret reference
exists. They must not include raw secret references.

Proposal-to-grant application is not implemented. Users may inspect proposal
details and create or delegate grants explicitly.

### Docs and skill

Public docs and the runtime-agnostic skill describe how agents can ask for
narrower delegated grants instead of asking for raw secrets.

## Boundaries

- This does not add process sandboxing.
- This does not prevent local processes with `CTXA_HOME` write access from
  editing local config.
- This does not add a network service dependency.
- This does not add budget accounting or spend controls.
- This does not add arbitrary policy expressions inside grants.

## Acceptance criteria covered

- Config validation accepts root and child HTTP grants that satisfy subset rules.
- Config validation rejects broader child methods, broader child path prefixes,
  child grants under non-delegable parents, over-depth child delegation, child
  secret references, subject/profile drift, missing profiles, and cycles.
- `ctxa grants create-https` creates a root grant without printing the secret
  reference.
- `ctxa grants delegate` creates a child grant only when it is a subset of the
  parent.
- Grant mutation audit events never include raw secret references.
- `ctxa grants show` redacts the secret reference and prints grant-chain ids.
- `ctxa profile test` allows URLs covered by profile-held grants.
- `ctxa run` proxy requests are allowed by profile-held grants and resolve the
  root secret reference internally.
- Proxy receipts for grant-backed requests include grant-chain metadata without
  raw secret values or secret references.
- Existing profile resources continue to work.
- Full gate passes:

```text
cargo fmt --all -- --check
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
bazel test //:full_suite
```
