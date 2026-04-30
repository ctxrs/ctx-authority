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
- Bitwarden Secrets Manager through `bws secret get`
- Doppler through `doppler secrets get`
- Infisical through `infisical secrets get`
- HashiCorp Vault through `vault kv get`
- AWS Secrets Manager through `aws secretsmanager get-secret-value`
- AWS SSM Parameter Store through `aws ssm get-parameter`
- GCP Secret Manager through `gcloud secrets versions access`
- Azure Key Vault through `az keyvault secret show`
- SOPS encrypted files through `sops --decrypt --extract`
- trusted local command backend for local escape-hatch integrations

## Backend contract

Backends support:

- validate configuration through backend construction and resolution
- resolve logical secret reference
- return secrets only to the broker execution path
- redact values from errors and debug output

The implementation exposes a `SecretBackend` trait, redacted `SecretLease`
values, and a serializable `SecretBackendConfig` factory for selecting fake,
`.env`, OS keychain, password manager, developer secret, cloud secret, encrypted
file, and trusted command backends without binding the main CLI to a hosted
control plane. Agent-facing execution builds its backend only from trusted local
configuration. If a backend is configured but cannot be loaded, execution fails
closed. The CLI must not silently fall back to the fake backend or another
weaker source.

CLI-backed backends run provider CLIs directly with `Command`, never through a
shell. Each command has a timeout, captures stdout and stderr, and returns only
generic provider errors. Errors must not include command stdout, command stderr,
the raw reference, or provider arguments. Backends that parse JSON preserve the
exact JSON string value; plain stdout backends remove at most one terminal line
ending.

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

## CLI-backed provider backends

These backends use local provider CLIs and the user's existing provider
authentication state. They do not create hosted ctx accounts, OAuth apps, or
provider-side credentials.

Supported reference forms:

| Backend type | Reference form | Command shape |
| --- | --- | --- |
| `bitwarden-secrets-manager` | `bws://<secret-id>` | `bws secret get <secret-id> --output json` and JSON pointer `/value` |
| `doppler` | `doppler://<name>` | `doppler secrets get <name> --plain` plus optional project/config flags |
| `infisical` | `infisical://<name>` | `infisical secrets get <name> --plain --silent` plus optional env/path/project flags |
| `hashicorp-vault` | `vault://<path>#<field>` | `vault kv get [-mount=<mount>] -field=<field> <path>` |
| `aws-secrets-manager` | `aws-secretsmanager://<secret-id>` | `aws secretsmanager get-secret-value --secret-id <secret-id> --output json` and JSON pointer `/SecretString` |
| `aws-ssm-parameter-store` | `aws-ssm://<name>` | `aws ssm get-parameter --name <name> --with-decryption --output json` and JSON pointer `/Parameter/Value` |
| `gcp-secret-manager` | `gcp-secretmanager://<name>` or `gcp-secretmanager://<name>#<version>` | `gcloud secrets versions access <version> --secret <name>` |
| `azure-key-vault` | `azure-keyvault://<name>` | `az keyvault secret show --vault-name <vault> --name <name> --query value -o tsv` |
| `sops` | `sops://<key>` or `sops:///<nested>/<key>` | `sops --decrypt --extract <expression> <file>` |

All provider CLI paths are configurable. Optional `timeout_ms` values override
the default command timeout. AWS commands add noninteractive pager and auto-prompt
flags. Infisical sets `INFISICAL_DISABLE_UPDATE_CHECK=true`. AWS Secrets Manager
currently resolves `SecretString`; `SecretBinary` values fail closed.

Example:

```yaml
secret_backend:
  type: aws-secrets-manager
  profile: dev
  region: us-east-1
  timeout_ms: 10000
```

Then a profile resource can reference:

```yaml
secret_ref: aws-secretsmanager://example-service/example-token
```

Provider-side audit logs may include secret identifiers or parameter names. Do
not use sensitive values as provider object names or `secret_ref` identifiers.

## Trusted command backend

The trusted command backend is an escape hatch for local integrations that do
not yet have a compiled backend. It is configured with a trusted local command
and argument templates. `{ref}` is replaced with the backend reference as a
single argument value; no shell is used.

Example:

```yaml
secret_backend:
  type: trusted-command
  command: /usr/local/bin/example-secret
  args: ["read", "{ref}", "--json"]
  json_pointer: /value
```

This backend is intentionally not a general plugin system. The command is trusted
local configuration and must preserve the same redaction and fail-closed
expectations as compiled backends.

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

Read-only secret backends resolve existing credentials. Provider-native token
issuers, such as GitHub app installation tokens, AWS STS credentials, OAuth
tokens, or restricted payment keys, are capability adapter work because they mint
new authority and need different receipts and policy semantics.
