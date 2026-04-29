# Local broker behavior

## User

A technical user running local agent tools.

## Problem

The user wants agents to perform useful actions with real credentials, while keeping durable raw secrets out of the agent's context.

## Primary run loop

1. User initializes `ctxa`.
2. User creates an agent profile.
3. User configures a secret backend.
4. User adds one or more HTTP resources to the profile.
5. User starts an agent command with `ctxa run --profile <id> -- <command>`.
6. Broker starts a loopback HTTP proxy and injects proxy environment variables.
7. Agent sends supported HTTP requests through the proxy.
8. Broker evaluates the profile rule.
9. Broker denies or forwards the request with broker-managed auth.
10. Broker records audit events and signed receipt metadata.

## Explicit action loop

The JSON action request path is still supported for policy development and deterministic adapter tests:

1. User writes and trusts a policy.
2. Agent requests an action through the CLI.
3. Broker evaluates policy.
4. Broker denies, allows, or requests approval.
5. Broker executes through a provider adapter if allowed.
6. Broker records audit events.
7. Broker emits a signed receipt.

## Supported commands

```bash
ctxa init
ctxa profile create github-reader --agent my-agent
ctxa profile add-http github-reader --id github-issues --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo/issues
ctxa run --profile github-reader -- my-agent
ctxa policy trust --id default --path policy.yaml
ctxa agent create demo --policy default
ctxa policy check --policy policy.yaml --file action.json
ctxa action request --file action.json
ctxa log
ctxa receipts verify receipt.json
ctxa mcp serve
```

`run` is the ergonomic surface for launching an agent under a profile. It starts a loopback HTTP proxy bound to `127.0.0.1` on an ephemeral port, injects proxy env vars, passes stdio through, stops the proxy after child exit, and returns the child exit code.

`policy check` is a diagnostic surface and may take an explicit policy path. `action request` is an execution surface and uses the trusted policy attached to the configured local agent profile; agents cannot supply policy paths at execution time.

The MCP server exposes metadata and structural receipt verification. It does not execute actions.

## Offline test scenario

The repository includes a deterministic offline scenario:

- a fake provider action allowed by policy succeeds
- a denied action does not reach the provider adapter
- approval-required actions fail closed without a configured human approval provider
- test-only approval providers cover approved and rejected approval outcomes
- receipts verify offline
- run profiles can inject proxy environment without exposing backend secrets
- the local proxy requires per-run proxy auth before resolving secrets
- the local proxy injects broker-managed bearer auth for allowed HTTP requests
- proxy receipts verify offline
- tampered receipts fail verification
- the fake secret sentinel does not appear in logs, receipts, stdout, stderr, or generated local state

## Release gate

The supported local gate is:

```text
bazel test //:full_suite
```

The full suite runs formatting, Clippy, Cargo tests, CLI smoke tests, and leak scanning through the repository wrappers.
