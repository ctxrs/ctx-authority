# Quality score

This file tracks implementation readiness. Update it as the product is built.

## Current grade

Early implementation with SDLC gates.

## Domains

| Domain | Grade | Notes |
| --- | --- | --- |
| CLI | Not started | Command surface drafted only. |
| Local daemon | Not started | Needs stack decision. |
| MCP server | Not started | Needs SDK decision. |
| Policy engine | Not started | YAML schema drafted. |
| Secret backends | Not started | Backend interface needed. |
| Provider adapters | Not started | Fake-first contract needed. |
| Approvals | Not started | CLI/TUI vs local web UI undecided. |
| Audit log | Not started | SQLite recommended. |
| Receipts | Not started | JWS/COSE/custom envelope undecided. |
| Tests | Partial | Unit tests, Bazel wrappers, CLI smoke test, and leak scan are wired. More acceptance coverage is still needed. |
| Security docs | Draft | Threat model needs implementation detail. |
| CI | Partial | Public workflow runs Cargo format, Clippy, Cargo tests, and Bazel unit/smoke/leak gates. |

## Quality bar

The MVP should not launch until the fake-provider test suite proves:

- secrets do not leak
- policies default closed
- denied actions do not execute
- approvals bind to payload hash
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
