# ctx authority

Local capability control for AI agents.

`ctx authority` lets agents use real tools without handing them raw secrets. An agent asks for an action, `ctxa` checks policy, requests approval when needed, executes through a provider adapter, writes an audit log, and returns a signed receipt.

This project is part of [ctx](https://ctx.rs).

```text
agent -> ctxa -> policy -> approval -> provider -> receipt
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

From this repository:

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

Trust a policy and attach it to an agent:

```sh
ctxa policy trust --id default --path tests/fixtures/demo-policy.yaml
ctxa agent create demo --policy default
```

Check an action against a policy:

```sh
ctxa policy check \
  --policy tests/fixtures/demo-policy.yaml \
  --file tests/fixtures/demo-action.json
```

Request the action through the trusted local broker:

```sh
ctxa action request --file tests/fixtures/demo-action.json
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

A named actor with an attached trusted policy.

**Policy**

A local YAML document that grants scoped capabilities. Execution uses the policy hash pinned by `ctxa policy trust`; agents cannot provide a policy path at action time.

**Capability**

A type of action, such as `http.request` or `email.send`.

**Secret Backend**

A configured source for credentials. The broker resolves secrets inside the execution path and passes them to provider adapters without exposing raw values to the agent.

**Receipt**

A signed record of the action, policy hash, payload hash, approval state, and provider result.

## Current Capabilities

- `ctxa` CLI for local initialization, policy checks, action requests, audit logs, and receipt verification
- local YAML policies with hash-pinned trust
- fail-closed approval behavior for approval-required actions
- SQLite audit log
- canonical JSON action hashes
- Ed25519-signed receipts
- structural MCP receipt verification
- pluggable secret backend interface
- `.env`, OS keychain, 1Password CLI, and test backends
- deterministic fake providers for closed-system tests

## MCP

`ctxa mcp serve` starts a stdio MCP server. The current server exposes broker metadata and structural receipt verification.

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

The Bazel wrappers keep Cargo build output outside the repository and use the shared ctx cache when available.

## Repository

- [ARCHITECTURE.md](ARCHITECTURE.md): system layout and boundaries
- [docs/product-specs](docs/product-specs): behavior specs and acceptance criteria
- [docs/SECURITY.md](docs/SECURITY.md): security model
- [skills/authority-broker](skills/authority-broker): agent instructions for using `ctxa`

## Planned Work

- human approval UI
- real provider adapters
- hosted ctx authority service
- additional secret backends
- richer MCP action surfaces
- admin and team policy workflows
