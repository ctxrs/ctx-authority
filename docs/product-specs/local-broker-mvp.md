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
5. User writes policy.
6. Agent requests an action through CLI or MCP.
7. Broker evaluates policy.
8. Broker denies, allows, or requests approval.
9. Broker executes through provider adapter if allowed.
10. Broker records audit event.
11. Broker emits signed receipt.

## Required commands

Candidate commands:

```bash
ctxa init
ctxa agent create demo
ctxa policy check --agent demo --file action.json
ctxa action request --agent demo --file action.json
ctxa approve
ctxa log
ctxa receipts verify receipt.json
ctxa mcp serve
```

## Closed-system demo

The demo must run without internet:

- fake secret backend contains `FAKE_GITHUB_TOKEN`.
- fake GitHub provider accepts the secret internally.
- policy allows fake GitHub read.
- policy requires approval for fake Mailgun send.
- approval is accepted locally.
- fake Mailgun records execution.
- receipt verifies.

## Done means

All acceptance tests in the active execution plan pass with fake providers only.
