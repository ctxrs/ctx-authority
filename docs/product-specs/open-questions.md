# Open questions

## Implementation stack

Decision: implement the first broker in Rust.

Initial implementation choices:

- CLI: `clap`
- async runtime: `tokio`
- local DB: `rusqlite`
- config: `serde` plus `serde_yaml`
- JSON: `serde_json`
- signing: Ed25519, with canonical JSON rules defined before receipt signing
- test orchestration: Bazel wrapper targets over Cargo and smoke scripts

## Process model

Should v1 be:

- CLI-only, spawning per action
- long-running local daemon with CLI client
- CLI first, daemon added before HN

## Secret backends

Which backends must ship in the first public release?

- fake backend
- `.env`
- macOS Keychain
- Windows Credential Manager
- Linux Secret Service/libsecret
- 1Password

Decision: fake, `.env`, macOS Keychain, Windows Credential Manager, Linux Secret
Service/libsecret, and 1Password are the launch group. Infisical and Doppler are
fast-follow backends.

## Plugin model

Should secret backends and provider adapters be:

- compiled-in
- subprocess plugins
- WASM plugins
- local HTTP plugins

Decision: compiled-in first, define a stable adapter trait/schema, then add
external plugins after the security boundary is clearer.

## Receipt signing

Should receipts use:

- JWS
- COSE
- custom canonical JSON plus Ed25519

## Local UI

Should v1 include a local web approval UI, or only CLI/TUI approval?

Current recommendation: CLI/TUI first. Add local web UI only if it materially
improves demo and can be tested deterministically.

## Telemetry

Should telemetry be absent, opt-in, or anonymous by default?

Current recommendation: no telemetry or explicit opt-in for public MVP.
