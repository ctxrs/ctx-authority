# Execution plan: build system and branching

## Goal

Make the repository safe for multi-agent development with fast local feedback,
externalized build output, and a dev-to-main promotion flow.

## Branch model

- `main`: publishable branch. Promote only after the full suite passes.
- `dev`: integration branch. Agents merge completed, reviewed lanes here.
- `lane/*`: short-lived implementation branches/worktrees.

## Promotion flow

1. Create a focused `lane/*` branch or worktree from current `dev`.
2. Keep changes scoped and public-safe. Do not include private context,
   credentials, or customer data.
3. Before opening or updating a pull request into `dev`, run:

   ```text
   bazel test //:unit_tests //:cli_smoke_tests //:leak_scan
   cargo test --all-targets --all-features --locked
   ```

4. Merge the reviewed lane into `dev` only after those checks pass.
5. Promote `dev` to `main` only after the full suite passes on the exact commit
   being promoted:

   ```text
   bazel test //:full_suite
   ```

6. If a release branch is needed later, cut it from `main` after promotion
   rather than merging lane branches directly to release.

## Build output

Cargo build artifacts and `sccache` state should live outside the repo and off
the internal drive when possible. Bazel wrapper scripts and sourced local dev
shells use this external cache root when it is available:

```text
/Volumes/ctx-cache/authority-broker/target
/Volumes/ctx-cache/authority-broker/sccache
/Volumes/ctx-cache/authority-broker/cargo-home
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

Wrapper scripts must work both from a normal checkout and under Bazel runfiles.
They set `CARGO_HOME`, `CARGO_TARGET_DIR`, and `SCCACHE_DIR` outside the
repository. Isolating `CARGO_HOME` prevents unrelated agent jobs from blocking
this repo on the shared package-cache lock. `sccache` is wired through
`AUTHORITY_BROKER_USE_SCCACHE=1`; it defaults off on Darwin because local
code-signing and external-volume policy issues can make the Rust wrapper flaky.
The repo must not commit a machine-specific `.cargo/config.toml`; developers can
create one locally if they want direct `cargo` commands to always use a custom
cache.

The CLI smoke test must exercise:

- `ctxa init`
- `ctxa agent create`
- `ctxa policy check`
- `ctxa action request`
- `ctxa receipts verify`
- `ctxa log`

It must fail if the fake secret sentinel `fake-secret-value` appears in command
stdout, stderr, receipts, audit output, or generated local state.

The leak scan is intentionally high-confidence. It should flag likely real
credentials and private-key material without banning public product language,
fake fixtures, or sanitized security guidance.

## Done means

- Cargo outputs use `/Volumes/ctx-cache` through Bazel/dev env scripts when it
  is available, with a temp-dir fallback.
- `sccache` is wired and can be enabled explicitly.
- Bazel targets exist and pass.
- `dev` exists and is used for integration.
- Public repo contains no private strategy or launch-plan content.
- CI runs the Cargo and Bazel gates on pushes and pull requests.
