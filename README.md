# ctx authority

Local capability control for AI agents.

`ctx authority` lets agents use real tools without handing them raw secrets. An agent asks for an action, `ctxa` checks policy, requests approval when needed, executes through a provider adapter, writes an audit log, and returns a signed receipt.

The main local workflow is `ctxa run`: a human starts an agent command inside a named profile, and `ctxa` gives that process a loopback profile proxy for the resources the profile allows.

This project is part of [ctx](https://ctx.rs). This repository is the source of truth for the `ctxa` CLI and local authority workflows.

```text
agent command -> ctxa run -> profile -> local proxy -> secret backend -> upstream API -> receipt
```

## Why

Agents are becoming useful enough to send email, call APIs, manage tickets, and operate services. Those actions need credentials and durable authority. Giving an agent a long-lived token or a password manager session is too broad.

`ctx authority` gives the agent capabilities instead of secrets:

- allow this agent to read GitHub issues
- let that agent delegate a narrower GitHub grant to a worker agent
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

Set up a runtime profile and install the agent instructions:

```sh
ctxa setup runtime codex --profile github-reader
```

For a manual setup, initialize local state and create the profile yourself:

```sh
ctxa init
ctxa profile create github-reader --agent my-agent
```

Configure a secret backend in the config file created by `ctxa init`, or in `$CTXA_HOME/config.yaml` when `CTXA_HOME` is set. This example uses 1Password secret references:

```yaml
secret_backend:
  type: one-password
```

Other local secret backends can use existing CLI sessions for Bitwarden Secrets
Manager, Doppler, Infisical, HashiCorp Vault, AWS Secrets Manager, AWS SSM
Parameter Store, GCP Secret Manager, Azure Key Vault, and SOPS-encrypted files.

Add an HTTPS resource to the profile:

```sh
ctxa profile add-https github-reader \
  --id github-issues \
  --host api.github.com \
  --secret-ref op://example-vault/github-token/token \
  --allow-method GET \
  --path-prefix /repos/example/repo/issues
```

Or create a delegable grant and delegate a narrower child grant:

```sh
ctxa profile create main-agent --agent main-agent
ctxa profile create worker-agent --agent worker-agent
ctxa grants create-https \
  --id github-root \
  --profile main-agent \
  --host api.github.com \
  --secret-ref op://example-vault/github-token/token \
  --allow-method GET \
  --path-prefix /repos/example/repo \
  --delegable \
  --max-depth 2
ctxa grants delegate \
  --from github-root \
  --id github-issues \
  --profile worker-agent \
  --allow-method GET \
  --path-prefix /repos/example/repo/issues
```

Child grants do not store or print the root secret reference. `ctxa` resolves
the root secret internally only when a matching brokered request runs.

Provider capability adapters are available when the agent should call a known
provider API through `ctxa` instead of through a generic proxy. This example lets
an agent read GitHub issues without seeing the GitHub token:

```sh
ctxa capability provider add-github \
  --id github \
  --token-ref op://example-vault/github-token/token

ctxa capability grant create \
  --id github-issues-read \
  --profile github-reader \
  --provider github \
  --capability github.issues.read \
  --resource github:example-org/example-repo

ctxa capability execute \
  --profile github-reader \
  --provider github \
  --capability github.issues.read \
  --resource github:example-org/example-repo \
  --operation '{"state":"open"}'
```

The command returns the provider response plus a signed receipt. The receipt
names the exact capability, resource, grant, provider request id, and credential
reference hash; it does not include the bearer token or raw credential
reference. GitHub providers can use a bearer token or a GitHub App installation
token minted from a locally supplied app JWT. Google and Microsoft providers use
bring-your-own bearer tokens from the configured secret backend.

Check the profile before launching an agent:

```sh
ctxa profile test github-reader \
  --method GET \
  --url https://api.github.com/repos/example/repo/issues
ctxa profile test worker-agent \
  --method GET \
  --url https://api.github.com/repos/example/repo/issues/1
ctxa doctor --profile github-reader
```

Run an agent command inside the profile:

```sh
ctxa run --profile github-reader -- my-agent
ctxa run --profile worker-agent -- worker-agent-command
```

The child process receives `HTTP_PROXY`, `HTTPS_PROXY`, common local CA trust variables, `CTXA_PROXY_URL`, `CTXA_PROXY_TOKEN`, and `CTXA_PROFILE`. Supported HTTP and HTTPS requests through that proxy are checked against the profile, receive broker-managed bearer auth, and produce local audit events plus signed receipt metadata. HTTPS support uses a process-scoped local CA for the launched child process; `ctxa` does not install a CA into the system trust store.

If a profile denies an authenticated request, inspect redacted local proposals:

```sh
ctxa proposals list
ctxa proposals show <proposal-id>
ctxa proposals apply <proposal-id> --secret-ref op://example-vault/github-token/token
```

The structured action API is available when an agent or tool submits an
explicit JSON action request. The `examples/` directory includes a local
fake-provider policy and action for trying that path:

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

Inspect local receipts:

```sh
ctxa receipts list
ctxa receipts show <receipt-id>
```

## Concepts

**Agent**

A named actor or process represented by a profile.

**Profile**

A local configuration entry that defines non-secret child environment values,
scoped HTTP resources, and grants held by a `ctxa run` process.

**Grant**

A structured unit of HTTP authority held by a profile. A delegable grant can
mint child grants that are mechanically narrower than the parent grant. Child
grants reference their parent and do not copy root secret references.

**Capability Grant**

A structured unit of provider authority held by a profile. Capability grants
bind a profile to a provider id, named capabilities, and typed resources such as
`github:owner/repo`, `google:gmail`, or `microsoft:outlook`. Delegated child
grants must stay within the parent provider, capabilities, resources, and
delegation depth.

**Policy**

A local YAML document that grants scoped capabilities for explicit JSON action requests. Execution uses the policy hash pinned by `ctxa policy trust`; agents cannot provide a policy path at action time.

**Capability**

A type of action, such as `http.request`, `email.send`, or
`github.issues.read`.

**Secret Backend**

A configured source for credentials. The broker resolves secrets inside the execution path and passes them to provider adapters without exposing raw values to the agent.

**Profile Proxy**

A loopback proxy created per `ctxa run`. It requires a per-run proxy credential,
matches HTTP and HTTPS requests to profile resources or profile-held grants,
strips caller-supplied auth and proxy headers, injects broker-managed bearer
auth, and records redacted audit metadata.

**Receipt**

A signed record of the action, policy hash, payload hash, approval state, and provider result.

## Supported Capabilities

- `ctxa` CLI for local initialization, policy checks, action requests, audit logs, and receipt verification
- run profiles with `ctxa profile create`, `ctxa profile add-http`, `ctxa profile add-https`, and `ctxa run`
- loopback credential proxy for profile-scoped HTTP and HTTPS requests
- attenuable HTTP grants with `ctxa grants create-http`, `ctxa grants create-https`, `ctxa grants delegate`, `ctxa grants list`, and `ctxa grants show`
- provider capability adapters for GitHub, Google, and Microsoft Graph through `ctxa capability`
- attenuable provider capability grants with `ctxa capability grant create`, `ctxa capability grant delegate`, `ctxa capability grant list`, and `ctxa capability grant show`
- capability execution receipts with provider request metadata and redacted credential reference hashes
- redacted proposal events for authenticated requests denied by profile policy
- proposal apply and dismiss workflow for turning denied requests into profile resources
- local diagnostics with `ctxa doctor`, `ctxa ca status`, and `ctxa profile test`
- local YAML policies with hash-pinned trust
- fail-closed approval behavior for approval-required actions
- SQLite audit log
- canonical JSON action hashes
- Ed25519-signed receipts
- local receipt list/show/verify workflow
- structural MCP receipt verification
- MCP tools for capability grant list/show/delegate and capability execution
- pluggable secret backend interface
- `.env`, OS keychain, 1Password CLI, Bitwarden Secrets Manager, Doppler, Infisical, HashiCorp Vault, AWS Secrets Manager, AWS SSM Parameter Store, GCP Secret Manager, Azure Key Vault, SOPS, trusted local command, and test backends

## Limits

- HTTPS proxying is process-scoped to the launched child process and currently supports HTTP/1.1 clients that honor standard proxy and CA environment variables.
- `ctxa` does not install or persist a local CA.
- `ctxa` does not sandbox the child process or stop it from using other local tools.
- Grant mutation commands modify local config and are not a sandbox boundary against local processes with write access to `CTXA_HOME`.
- Secret backends protect the supported broker path; `.env` files remain readable by any process with filesystem access.
- CLI-backed secret backends use the user's existing provider CLI login/session and may be subject to provider-side audit logs for secret identifiers.
- Receipts and audit events are local artifacts unless you move or publish them yourself.

## MCP

`ctxa mcp serve` starts a stdio MCP server for broker metadata, structural
receipt verification, profile-bound capability grant delegation, and granted
provider capability execution.

```sh
ctxa mcp serve
```

Capability mutation and execution tools require the MCP server process to be
bound to a profile with `CTXA_PROFILE` or `CTXA_MCP_PROFILE`. When `ctxa` starts
an agent through `ctxa run`, `CTXA_PROFILE` is provided automatically.

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

Closed-system tests use deterministic fake providers and fake secret backends so
the suite can run without external services.

## Repository

- [ARCHITECTURE.md](ARCHITECTURE.md): system layout and boundaries
- [docs/product-specs](docs/product-specs): behavior specs and acceptance criteria
- [docs/SECURITY.md](docs/SECURITY.md): security model
- [skills/ctx-authority](skills/ctx-authority): agent instructions for using `ctxa`
