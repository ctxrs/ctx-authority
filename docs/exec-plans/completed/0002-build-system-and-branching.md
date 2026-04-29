# Completed plan: build system and branching

## Outcome

The repository has Bazel wrapper targets for granular local feedback, Cargo build output outside the repository, and a `dev` to `main` promotion flow.

## Branch model

- `main`: publishable branch after the full suite passes
- `dev`: integration branch for reviewed work
- `lane/*`: short-lived implementation branches or worktrees

## Promotion flow

1. Create a focused `lane/*` branch or worktree from current `dev`.
2. Keep changes scoped and public-safe.
3. Before opening or updating a pull request into `dev`, run:

   ```text
   bazel test //:unit_tests //:cli_smoke_tests //:leak_scan
   cargo test --all-targets --all-features --locked
   ```

4. Merge the reviewed lane into `dev` only after those checks pass.
5. Promote `dev` to `main` only after the full suite passes on the exact commit being promoted:

   ```text
   bazel test //:full_suite
   ```

## Build output

Wrapper scripts set `CARGO_TARGET_DIR` and `SCCACHE_DIR` outside the repository. `AUTHORITY_BROKER_CACHE_ROOT` can override the cache root; when unset, the scripts use the shared ctx cache when available and a temp-dir fallback otherwise.

`CARGO_HOME` defaults to `/tmp/authority-broker-cargo-home` and can be overridden with `AUTHORITY_BROKER_CARGO_HOME`. `sccache` can be enabled with `AUTHORITY_BROKER_USE_SCCACHE=1`.

The repo does not commit a machine-specific `.cargo/config.toml`.

## Available targets

- `//:fmt_check`
- `//:clippy_check`
- `//:unit_tests`
- `//:cli_smoke_tests`
- `//:leak_scan`
- `//:full_suite`

## CLI smoke coverage

The CLI smoke test exercises:

- `ctxa init`
- `ctxa agent create`
- `ctxa policy check`
- `ctxa action request`
- `ctxa receipts verify`
- `ctxa log`

It fails if the fake secret sentinel appears in command stdout, stderr, receipts, audit output, or generated local state.
