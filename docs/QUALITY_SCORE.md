# Quality score

This file tracks implementation readiness. Update it as the product is built.

## Current grade

Early implementation with SDLC gates.

## Domains

| Domain | Grade | Notes |
| --- | --- | --- |
| CLI | Partial | Core init/agent/policy/action/log/receipt commands implemented. |
| Local daemon | Not started | Planned after CLI surface stabilizes. |
| MCP server | Partial | Initialize, ping, tool list, capabilities, and structural receipt verification are implemented. Action execution is planned. |
| Policy engine | Partial | v1 YAML allow/deny/approval decisions implemented with strict field and version validation. |
| Secret backends | Partial | Fake, `.env`, OS keychain abstraction, and 1Password adapter are implemented. |
| Provider adapters | Partial | Fake provider adapter implemented; real adapters are not in v1. |
| Approvals | Partial | Explicit test approval/rejection and fail-closed default implemented. Human TUI/daemon approval is planned. |
| Audit log | Partial | SQLite audit implemented for decisions, attempts, successes, and failures. |
| Receipts | Partial | Canonical JSON plus Ed25519 signing and local verification implemented. |
| Tests | Partial | Unit tests, integration tests, Bazel wrappers, CLI smoke test, and leak scan are wired. More acceptance coverage is still needed. |
| Security docs | Draft | Threat model needs implementation detail. |
| CI | Partial | Public workflow runs Cargo format, Clippy, Cargo tests, and Bazel unit/smoke/leak gates. |

## Quality bar

The MVP should not launch until the fake-provider test suite proves:

- secrets do not leak
- policies default closed
- denied actions do not execute
- approvals bind to canonical action hash
- receipts verify offline
- tampered receipts fail

## Current gates

Run these before merging a lane branch into `dev`:

```text
bazel test //:unit_tests //:cli_smoke_tests //:leak_scan
cargo test --all-targets --all-features --locked
```

Run this before promoting `dev` to `main`:

```text
bazel test //:full_suite
```
