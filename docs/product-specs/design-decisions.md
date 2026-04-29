# Design decisions

## Implementation stack

The broker is implemented in Rust.

Implementation choices:

- CLI: `clap`
- async runtime: none in the initial CLI path
- local DB: `rusqlite`
- config: `serde` plus `serde_yaml`
- JSON: `serde_json`
- signing: canonical JSON plus Ed25519
- test orchestration: Bazel wrapper targets over Cargo and smoke scripts

## Process model

The command surface is CLI-first. Commands load trusted local configuration,
evaluate policy, execute through broker-owned adapters, and write local audit
and receipt records.

## Secret backends

The initial backend set is:

- fake backend for tests
- `.env`
- OS keychain through the platform credential store
- 1Password through `op read`

## Plugin model

Backends and provider adapters are compiled in. This keeps the execution and
redaction boundary inspectable in the repository.

## Receipt signing

Receipts use canonical JSON plus Ed25519. The `receipt_version` field makes the
current envelope explicit.

## Approval behavior

Approval-required actions fail closed unless an approval provider is configured.
The default public CLI does not expose a test auto-approval mode.

## Telemetry

Telemetry is disabled by default. Any telemetry should require explicit opt-in.
