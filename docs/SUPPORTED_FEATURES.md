# Supported features

This page summarizes the local broker surfaces that are implemented in this
repository.

## Feature matrix

| Area | Support | Notes |
| --- | --- | --- |
| CLI | Implemented | Core init/profile/run/agent/policy/action/log/receipt commands are implemented. |
| Run profiles | Implemented | `ctxa run` starts a host-mode loopback proxy for scoped HTTP and HTTPS profile resources. `--clean-env` is available for stricter child environment hygiene. HTTPS support is process-scoped to the launched child process. |
| Grants | Implemented | HTTP grants can be delegated into mechanically narrower child grants. Grant-backed proxy requests resolve the root secret internally and emit receipts with redacted grant-chain metadata. |
| MCP server | Implemented | Initialize, ping, tool list, capabilities, local Ed25519 receipt verification, capability grant inspection/delegation, and capability execution are implemented. |
| Policy engine | Implemented | YAML allow/deny/approval decisions use strict field and version validation. |
| Secret backends | Implemented | Fake, `.env`, OS keychain abstraction, 1Password, Bitwarden Secrets Manager, Doppler, Infisical, HashiCorp Vault, AWS Secrets Manager, AWS SSM Parameter Store, GCP Secret Manager, Azure Key Vault, SOPS, and trusted local command adapters are implemented. |
| Provider adapters | Implemented | Fake provider adapter, profile proxy execution path, and local BYO-token GitHub/Google/Microsoft capability adapters are implemented. |
| Proposals | Implemented | Authenticated profile-proxy denials record redacted local proposal events that can be shown, applied, or dismissed. |
| Diagnostics | Implemented | `ctxa doctor`, `ctxa ca status`, and `ctxa profile test` are implemented. |
| Approvals | Limited | Approval-required actions fail closed unless an approval provider is configured. |
| Audit log | Implemented | SQLite audit covers decisions, attempts, successes, and failures. |
| Receipts | Implemented | Canonical JSON plus Ed25519 signing, local list/show, and local verification are implemented. |

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
