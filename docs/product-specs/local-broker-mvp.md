# Local broker MVP

## User

A technical agent power user running local agents.

## Problem

The user wants agents to perform useful actions with real credentials, but does
not want to expose durable raw secrets to the agent.

## MVP loop

1. User initializes `ctxa`.
2. User creates an agent profile.
3. User configures a secret backend.
4. User configures provider resources.
5. User writes and trusts a policy.
6. Agent requests an action through CLI.
7. Broker evaluates policy.
8. Broker denies, allows, or requests approval.
9. Broker executes through provider adapter if allowed.
10. Broker records audit event.
11. Broker emits signed receipt.

## Required commands

Candidate commands:

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

`policy check` is a diagnostic surface and may take an explicit policy path.
`action request` is an execution surface and must use the trusted policy attached
to the configured local agent profile; agents must not supply policy paths at
execution time.

The current MCP server exposes metadata and structural receipt verification.
MCP action execution and approval polling are planned follow-ups.

## Closed-system demo

The demo must run without internet:

- fake secret backend contains `FAKE_GITHUB_TOKEN`.
- fake GitHub provider accepts the secret internally.
- policy allows fake GitHub read.
- policy requires approval for fake Mailgun send.
- approval-required actions fail closed until a real local approval provider is
  implemented.
- fake Mailgun approval execution is covered only through internal runtime
  tests.
- receipt verifies.

## Current closed-system gate

The current automated gate covers the CLI flow with fake providers, including
policy allow/deny/approval-required decisions, fail-closed approval behavior,
audit records, local receipt signature verification, tamper rejection, and
fake-secret leak checks. Internal runtime tests cover approved/rejected approval
records without exposing caller-controlled approval to the agent-facing CLI. MCP
coverage is limited to the implemented metadata and receipt-shape tools until
action execution is added to MCP.

## Done means

The current release is publishable when the CLI acceptance tests, MCP metadata
tests, leak scan, code review, and `bazel test //:full_suite` pass.
