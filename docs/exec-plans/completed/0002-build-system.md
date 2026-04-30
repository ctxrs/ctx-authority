# Completed plan: build system

## Outcome

The repository has Bazel wrapper targets for granular local feedback and Cargo
build output outside the repository.

## Quality gates

Use focused changes and run the smallest relevant gate while iterating. Before
publishing a change, run:

```text
bazel test //:full_suite
```

Useful narrower gates are:

```text
bazel test //:unit_tests //:cli_smoke_tests //:leak_scan
cargo test --all-targets --all-features --locked
```

## Build output

Wrapper scripts set `CARGO_TARGET_DIR` and `SCCACHE_DIR` outside the repository. `CTXA_CACHE_ROOT` can override the cache root; when unset, the scripts use a temp-dir cache.

`CARGO_HOME` defaults to `/tmp/ctxa-cargo-home` and can be overridden with `CTXA_CARGO_HOME`. `sccache` can be enabled with `CTXA_USE_SCCACHE=1`.

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
