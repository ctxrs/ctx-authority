# Completed plan: local broker

## Outcome

The repository includes a local-first `ctxa` broker that lets an agent request fake-provider actions through policy, fail-closed approval behavior, audit logging, and signed receipts without requiring real provider credentials.

## Completed work

- chose Rust implementation stack
- implemented CLI and test runner
- defined config and policy schema
- implemented fake and local secret backends
- implemented fake provider adapter
- implemented allow, deny, and approval-required policy decisions
- implemented fail-closed approval behavior plus test-only approval providers
- implemented SQLite audit log
- implemented receipt signing and verification
- implemented minimal MCP server for metadata and structural receipt verification
- added closed-system acceptance tests
- added quickstart docs

## Covered behavior

- `ctxa init` creates local config
- `ctxa policy trust --id default --path policy.yaml` pins a policy hash
- `ctxa agent create demo --policy default` creates an executable trusted agent profile
- allowed fake actions succeed
- denied fake actions do not reach provider adapters
- approval-required actions fail closed without a configured human approval provider
- receipts verify offline
- tampered receipts fail verification
- the fake secret sentinel does not appear in logs, receipts, stdout, or stderr
- MCP tests cover implemented metadata and structural receipt verification tools

## Follow-up work

- human approval UI
- real provider adapters
- MCP action execution
- MCP approval state
- key-based receipt verification through MCP
