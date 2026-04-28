# Execution plan: build system and branching

## Goal

Make the repository safe for multi-agent development with fast local feedback,
externalized build output, and a dev-to-main promotion flow.

## Branch model

- `main`: publishable branch. Promote only after the full suite passes.
- `dev`: integration branch. Agents merge completed, reviewed lanes here.
- `lane/*`: short-lived implementation branches/worktrees.

## Build output

Cargo build artifacts and `sccache` state should live outside the repo and off
the internal drive when possible:

```text
/Volumes/ctx-cache/authority-broker/target
/Volumes/ctx-cache/authority-broker/sccache
```

## Test orchestration

Bazel should provide granular targets for routine checks while Cargo remains the
Rust build tool.

Expected targets:

- `//:fmt_check`
- `//:clippy_check`
- `//:unit_tests`
- `//:cli_smoke_tests`
- `//:leak_scan`
- `//:full_suite`

## Done means

- Cargo outputs use `/Volumes/ctx-cache`.
- `sccache` is wired.
- Bazel targets exist and pass.
- `dev` exists and is used for integration.
- Public repo contains no private strategy or launch-plan content.
