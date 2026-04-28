# Quality score

This file tracks implementation readiness. Update it as the product is built.

## Current grade

Pre-implementation.

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
| Tests | Not started | Acceptance criteria defined. |
| Security docs | Draft | Threat model needs implementation detail. |

## Quality bar

The MVP should not launch until the fake-provider test suite proves:

- secrets do not leak
- policies default closed
- denied actions do not execute
- approvals bind to payload hash
- receipts verify offline
- tampered receipts fail
