# Supported features

This page summarizes the local broker surfaces that are implemented in this
repository.

## Feature matrix

| Area | Support | Notes |
| --- | --- | --- |
| CLI | Implemented | Core init/profile/run/agent/policy/action/log/receipt commands are implemented. |
| Run profiles | Implemented | `ctxa run` starts a loopback HTTP proxy for scoped profile resources. HTTPS interception is not supported. |
| MCP server | Implemented | Initialize, ping, tool list, capabilities, and structural receipt verification are implemented. |
| Policy engine | Implemented | YAML allow/deny/approval decisions use strict field and version validation. |
| Secret backends | Implemented | Fake, `.env`, OS keychain abstraction, and 1Password adapter are implemented. |
| Provider adapters | Implemented | Fake provider adapter and HTTP proxy execution path are implemented. |
| Approvals | Limited | Approval-required actions fail closed unless an approval provider is configured. |
| Audit log | Implemented | SQLite audit covers decisions, attempts, successes, and failures. |
| Receipts | Implemented | Canonical JSON plus Ed25519 signing and local verification are implemented. |

## Test gates

The full local gate is:

```text
bazel test //:full_suite
```

Useful focused checks are:

```text
bazel test //:unit_tests //:cli_smoke_tests //:leak_scan
cargo test --all-targets --all-features --locked
```
