# Local broker behavior

## User

A technical user running local agent tools.

## Problem

The user wants agents to perform useful actions with real credentials, while keeping durable raw secrets out of the agent's context.

## Core loop

1. User initializes `ctxa`.
2. User creates an agent profile.
3. User configures a secret backend.
4. User writes and trusts a policy.
5. Agent requests an action through the CLI.
6. Broker evaluates policy.
7. Broker denies, allows, or requests approval.
8. Broker executes through a provider adapter if allowed.
9. Broker records audit events.
10. Broker emits a signed receipt.

## Supported commands

```bash
ctxa init
ctxa policy trust --id default --path policy.yaml
ctxa agent create demo --policy default
ctxa policy check --policy policy.yaml --file action.json
ctxa action request --file action.json
ctxa log
ctxa receipts verify receipt.json
ctxa mcp serve
```

`policy check` is a diagnostic surface and may take an explicit policy path. `action request` is an execution surface and uses the trusted policy attached to the configured local agent profile; agents cannot supply policy paths at execution time.

The MCP server exposes metadata and structural receipt verification. Action execution and approval polling over MCP are planned work.

## Offline test scenario

The repository includes a deterministic offline scenario:

- a fake provider action allowed by policy succeeds
- a denied action does not reach the provider adapter
- approval-required actions fail closed without a configured human approval provider
- test-only approval providers cover approved and rejected approval outcomes
- receipts verify offline
- tampered receipts fail verification
- the fake secret sentinel does not appear in logs, receipts, stdout, stderr, or generated local state

## Release gate

The supported local gate is:

```text
bazel test //:full_suite
```

The full suite runs formatting, Clippy, Cargo tests, CLI smoke tests, and leak scanning through the repository wrappers.
