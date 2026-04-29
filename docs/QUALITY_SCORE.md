# Release readiness

This file tracks current implementation status.

## Current status

Local CLI implementation with SDLC gates.

## Domains

| Domain | Grade | Notes |
| --- | --- | --- |
| CLI | Implemented | Core init/agent/policy/action/log/receipt commands are implemented. |
| Local daemon | Planned | Planned after CLI surface stabilizes. |
| MCP server | Implemented subset | Initialize, ping, tool list, capabilities, and structural receipt verification are implemented. Action execution is planned. |
| Policy engine | Implemented subset | v1 YAML allow/deny/approval decisions are implemented with strict field and version validation. |
| Secret backends | Implemented subset | Fake, `.env`, OS keychain abstraction, and 1Password adapter are implemented. |
| Provider adapters | Test adapters | Fake provider adapter is implemented; real adapters are planned. |
| Approvals | Implemented subset | Fail-closed CLI behavior and test-only approval-provider coverage are implemented. Human approval UI is planned. |
| Audit log | Implemented | SQLite audit covers decisions, attempts, successes, and failures. |
| Receipts | Implemented | Canonical JSON plus Ed25519 signing and local verification are implemented. |
| Tests | Implemented | Unit tests, integration tests, Bazel wrappers, CLI smoke test, and leak scan are wired. |
| Security docs | Current | Security model is documented against implemented behavior. |
| CI | Implemented | Public workflow runs Cargo format, Clippy, Cargo tests, and Bazel unit/smoke/leak gates. |

## Quality bar

The local release gate should prove:

- secrets do not leak
- policies default closed
- denied actions do not execute
- approvals bind to canonical action hash
- receipts verify offline
- tampered receipts fail

## Current gates

Useful focused checks:

```text
bazel test //:unit_tests //:cli_smoke_tests //:leak_scan
cargo test --all-targets --all-features --locked
```

Full repository gate:

```text
bazel test //:full_suite
```
