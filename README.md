# ctx authority

Local capability control for AI agents.

`ctx authority` lets agents use real tools without handing them raw secrets. An agent asks for an action, `ctxa` checks policy, requests approval when needed, executes through a provider adapter, writes an audit log, and returns a signed receipt.

The main local workflow is `ctxa run`: a human starts an agent command inside a named profile, and `ctxa` gives that process a loopback HTTP proxy for the resources the profile allows.

This project is part of [ctx](https://ctx.rs). Product pages and install docs live under `https://ctx.rs/authority`.

```text
agent command -> ctxa run -> profile -> local proxy -> secret backend -> upstream API -> receipt
```

## Why

Agents are becoming useful enough to send email, call APIs, manage tickets, and operate services. Those actions need credentials and durable authority. Giving an agent a long-lived token or a password manager session is too broad.

`ctx authority` gives the agent capabilities instead of secrets:

- allow this agent to read GitHub issues
- require approval before this agent sends email
- use this configured backend for secrets
- record what happened
- issue a receipt that can be verified later

## Install

With Homebrew:

```sh
brew install ctxrs/tap/ctxa
```

With Cargo:

```sh
cargo install --git https://github.com/ctxrs/ctx-authority --locked
```

From a local checkout:

```sh
cargo install --path .
```

Or run without installing:

```sh
cargo run --bin ctxa -- --help
```

## Quickstart

Initialize local state:

```sh
ctxa init
```

Create a run profile:

```sh
ctxa profile create github-reader --agent my-agent
```

Configure a secret backend in the config file created by `ctxa init`, or in `$CTXA_HOME/config.yaml` when `CTXA_HOME` is set. This example uses 1Password secret references:

```yaml
secret_backend:
  type: one-password
```

Add an HTTP resource to the profile:

```sh
ctxa profile add-http github-reader \
  --id github-issues \
  --host api.github.com \
  --secret-ref op://example-vault/github-token/token \
  --allow-method GET \
  --path-prefix /repos/example/repo/issues
```

Run an agent command inside the profile:

```sh
ctxa run --profile github-reader -- my-agent
```

The child process receives `HTTP_PROXY`, `http_proxy`, `CTXA_PROXY_URL`, `CTXA_PROXY_TOKEN`, and `CTXA_PROFILE`. Supported HTTP requests through that proxy are checked against the profile, receive broker-managed bearer auth, and produce local audit events plus signed receipt metadata. The proxy supports absolute-form `http://` requests; it does not intercept HTTPS `CONNECT`.

The lower-level action request path is available when an agent or tool submits a
structured action request:

```sh
ctxa policy check \
  --policy examples/demo-policy.yaml \
  --file examples/demo-action.json
```

Request the action through the trusted local broker:

```sh
ctxa policy trust --id demo --path examples/demo-policy.yaml
ctxa agent create demo --policy demo
ctxa action request --file examples/demo-action.json > receipt.json
```

Verify the resulting receipt:

```sh
ctxa receipts verify receipt.json
```

Inspect the audit log:

```sh
ctxa log
```

## Concepts

**Agent**

A named actor or process represented by a profile.

**Profile**

A local configuration entry that defines non-secret child environment values and scoped HTTP resources for `ctxa run`.

**Policy**

A local YAML document that grants scoped capabilities for explicit JSON action requests. Execution uses the policy hash pinned by `ctxa policy trust`; agents cannot provide a policy path at action time.

**Capability**

A type of action, such as `http.request` or `email.send`.

**Secret Backend**

A configured source for credentials. The broker resolves secrets inside the execution path and passes them to provider adapters without exposing raw values to the agent.

**HTTP Proxy**

A loopback proxy created per `ctxa run`. It requires a per-run proxy credential, matches requests to profile resources, strips caller-supplied auth and proxy headers, injects broker-managed bearer auth, and records redacted audit metadata.

**Receipt**

A signed record of the action, policy hash, payload hash, approval state, and provider result.

## Supported Capabilities

- `ctxa` CLI for local initialization, policy checks, action requests, audit logs, and receipt verification
- run profiles with `ctxa profile create`, `ctxa profile add-http`, and `ctxa run`
- loopback HTTP credential proxy for profile-scoped `http://` requests
- local YAML policies with hash-pinned trust
- fail-closed approval behavior for approval-required actions
- SQLite audit log
- canonical JSON action hashes
- Ed25519-signed receipts
- structural MCP receipt verification
- pluggable secret backend interface
- `.env`, OS keychain, 1Password CLI, and test backends
- deterministic fake providers for closed-system tests

## Limits

- The profile proxy supports HTTP proxy requests, not HTTPS interception.
- `ctxa` does not sandbox the child process or stop it from using other local tools.
- Secret backends protect the supported broker path; `.env` files remain readable by any process with filesystem access.
- Receipts and audit events are local artifacts unless you move or publish them yourself.

## MCP

`ctxa mcp serve` starts a stdio MCP server for broker metadata and structural receipt verification.

```sh
ctxa mcp serve
```

For cryptographic receipt verification, use:

```sh
ctxa receipts verify receipt.json
```

## Development

Run the Rust suite:

```sh
cargo test --all-targets --all-features --locked
```

Run the full repository gate:

```sh
bazel test //:full_suite
```

The Bazel wrappers keep Cargo build output outside the repository. Set
`CTXA_CACHE_ROOT` to choose a persistent cache location.

## Repository

- [ARCHITECTURE.md](ARCHITECTURE.md): system layout and boundaries
- [docs/product-specs](docs/product-specs): behavior specs and acceptance criteria
- [docs/SECURITY.md](docs/SECURITY.md): security model
- [skills/ctx-authority](skills/ctx-authority): agent instructions for using `ctxa`
