# Secret backends

Secret backends are pluggable so users can keep credentials in existing stores.

## Why pluggable

Users already keep secrets in different places. The broker should not become
the secret store of record. It should broker capability use across existing
stores.

## Implemented backends

Implemented:

- fake backend for tests
- `.env` backend for simple local use
- OS keychain through the platform store:
  - macOS Keychain
  - Windows Credential Manager
  - Linux Secret Service/libsecret
- 1Password through `op read`

## Backend contract

Backends support:

- validate configuration through backend construction and resolution
- resolve logical secret reference
- return secrets only to the broker execution path
- redact values from errors and debug output

The implementation exposes a `SecretBackend` trait, redacted `SecretLease`
values, and a serializable `SecretBackendConfig` factory for selecting fake,
`.env`, 1Password, and OS keychain backends without binding the main CLI to a
provider-specific workflow. Agent-facing execution builds its backend only from
trusted local configuration. If a backend is configured but cannot be loaded,
execution fails closed. The CLI must not silently fall back to the fake backend
or another weaker source.

## Reference model

The broker treats references as backend-scoped identifiers. A reference may be a
logical test key, an environment variable name, an OS keychain account name, or a
vendor reference such as a 1Password `op://` path.

Backend errors must not echo the reference value, resolved secret value, command
stdout, command stderr, or a raw `.env` line. References are usually less
sensitive than values, but keeping them out of errors avoids accidental leakage
when a caller supplies a secret value in the reference field by mistake.

## `.env` backend

The `.env` backend is for local development, onboarding, tests, and compatibility
with existing projects. It supports comments, optional `export`, unquoted values,
single-quoted values, double-quoted values with common escapes, empty values,
and escaped `#` characters. It does not expand variables or execute shell
syntax.

Parse errors report the line number and a generic reason only. They must not
include the raw line or parsed value.

## 1Password backend

The 1Password backend accepts only `op://` secret references and resolves them by
running:

```sh
op read "$REFERENCE"
```

`op read` is the public CLI command for reading the field identified by a
1Password secret reference. The backend reads stdout on success, removes one
terminal line ending, and preserves other whitespace in the secret value. On
failure it reports a generic provider error and does not include stdout, stderr,
or the reference.

References:

- 1Password CLI `read`: https://developer.1password.com/docs/cli/reference/commands/read/
- 1Password secret reference syntax: https://developer.1password.com/docs/cli/secret-reference-syntax/

## OS keychain backend

The OS keychain backend uses a small store abstraction around the platform
keychain adapter. Production code uses the system store; tests use deterministic
fake stores so the test suite never prompts for real keychain access and never
requires real credentials.

The configured service name scopes broker-owned entries. Explicit JSON action
requests resolve the trusted `default` reference for provider execution. Run
profile HTTP resources resolve their configured `secret_ref` only after proxy
authorization and profile matching succeed.

Reference: https://docs.rs/keyring/latest/keyring/

## Agent visibility

Agents may see logical capability/resource names. They should not receive raw
secret values.

Policy and audit output should expose only logical resource names and redacted
backend metadata. Proxy receipts may include a hash of the secret reference as
part of the profile rule hash, but they must not include the raw secret value.

## Notes

`.env` support is primarily for onboarding, tests, and compatibility. It is not
the strongest security story because agents may be able to read local project
files directly. The security story starts with OS keychains and remote BYO
providers such as 1Password.
