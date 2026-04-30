# Local broker behavior

## User

A technical user running local agent tools.

## Problem

The user wants agents to perform useful actions with real credentials, while keeping durable raw secrets out of the agent's context.

## Primary run loop

1. User initializes `ctxa`.
2. User creates an agent profile.
3. User configures a secret backend.
4. User adds one or more HTTP or HTTPS resources to the profile.
5. User optionally creates or delegates HTTP grants held by profiles.
6. User starts an agent command with `ctxa run --profile <id> -- <command>`.
7. Broker starts a loopback profile proxy and injects proxy environment variables.
8. Agent sends supported HTTP or HTTPS requests through the proxy.
9. Broker evaluates the profile resource or profile-held grant.
10. Broker denies or forwards the request with broker-managed auth.
11. Broker records audit events and signed receipt metadata.

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
ctxa profile add-https github-reader --id github-issues --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo/issues
ctxa profile create main-agent --agent main-agent
ctxa profile create worker-agent --agent worker-agent
ctxa grants create-https --id github-root --profile main-agent --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo --delegable --max-depth 2
ctxa grants delegate --from github-root --id github-issues --profile worker-agent --allow-method GET --path-prefix /repos/example/repo/issues
ctxa grants list --profile worker-agent
ctxa grants show github-issues
ctxa capability provider add-github --id github --token-ref op://example-vault/github-token/token
ctxa capability grant create --id github-cap-root --profile main-agent --provider github --capability github.issues.read --resource github:example/repo --delegable --max-depth 2
ctxa capability grant delegate --from github-cap-root --id github-cap-worker --profile worker-agent --capability github.issues.read --resource github:example/repo
ctxa capability grant list --profile worker-agent
ctxa capability grant show github-cap-worker
ctxa capability execute --profile worker-agent --provider github --capability github.issues.read --resource github:example/repo --operation '{"state":"open"}'
ctxa profile test github-reader --url https://api.github.com/repos/example/repo/issues
ctxa doctor --profile github-reader
ctxa run --profile github-reader -- my-agent
ctxa proposals list
ctxa proposals apply <proposal-id> --secret-ref op://example-vault/github-token/token
ctxa policy trust --id default --path policy.yaml
ctxa agent create demo --policy default
ctxa policy check --policy policy.yaml --file action.json
ctxa action request --file action.json
ctxa log
ctxa receipts list
ctxa receipts show <receipt-id>
ctxa receipts verify receipt.json
ctxa mcp serve
```

`run` is the ergonomic surface for launching an agent under a profile. It starts a loopback profile proxy bound to `127.0.0.1` on an ephemeral port, injects proxy env vars, passes stdio through, stops the proxy after child exit, and returns the child exit code.

`policy check` is a diagnostic surface and may take an explicit policy path. `action request` is an execution surface and uses the trusted policy attached to the configured local agent profile; agents cannot supply policy paths at execution time.

The MCP server exposes metadata, structural receipt verification, profile-bound
capability grant delegation, and granted provider capability execution.

## Offline test scenario

The repository includes a deterministic offline scenario:

- a fake provider action allowed by policy succeeds
- a denied action does not reach the provider adapter
- approval-required actions fail closed without a configured human approval provider
- test-only approval providers cover approved and rejected approval outcomes
- receipts verify offline
- run profiles can inject proxy environment without exposing backend secrets
- the local proxy requires per-run proxy auth before resolving secrets
- the local proxy injects broker-managed bearer auth for allowed HTTP and HTTPS requests
- authenticated profile-proxy denials create redacted local proposal events
- proposal application can turn a redacted denied request into a profile resource
- attenuable grant delegation creates child grants without copying root secret references
- profile-held grants can authorize proxy requests and emit redacted grant-chain receipt metadata
- proxy receipts verify offline
- tampered receipts fail verification
- the fake secret sentinel does not appear in logs, receipts, stdout, stderr, or generated local state

## Release gate

The supported local gate is:

```text
bazel test //:full_suite
```

The full suite runs formatting, Clippy, Cargo tests, CLI smoke tests, and leak scanning through the repository wrappers.
