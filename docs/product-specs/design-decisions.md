# Design decisions

## Implementation stack

The broker is implemented in Rust.

Initial implementation choices:

- CLI: `clap`
- async runtime: none in the initial CLI path
- local DB: `rusqlite`
- config: `serde` plus `serde_yaml`
- JSON: `serde_json`
- signing: canonical JSON plus Ed25519
- test orchestration: Bazel wrapper targets over Cargo and smoke scripts

## Process model

The command surface is CLI-first. A long-running local daemon can be added after the CLI and policy model are stable.

## Secret backends

The initial backend set is:

- fake backend for tests
- `.env`
- OS keychain through the platform credential store
- 1Password through `op read`

Infisical, Doppler, Bitwarden Secrets Manager, HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, and Azure Key Vault are adapter candidates.

## Plugin model

Backends and provider adapters are compiled in first. External plugin support comes after the local trait and security boundary are stable.

## Receipt signing

Receipts use canonical JSON plus Ed25519. JWS, COSE, and verifiable-credential-compatible envelopes can be added later through explicit receipt versioning.

## Local UI

The first approval behavior is CLI fail-closed behavior plus test-harness approval providers. A TUI, local web UI, or daemon-backed approval flow can be added when it has deterministic test coverage.

## Telemetry

Telemetry is disabled by default. Any telemetry should require explicit opt-in.
