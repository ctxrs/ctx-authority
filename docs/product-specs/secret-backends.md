# Secret backends

Secret backends should be pluggable from day one.

## Why pluggable

Users already keep secrets in different places. The broker should not become
the secret store of record. It should broker capability use across existing
stores.

## Initial backends

Required:

- fake backend for tests
- `.env` backend for simple local use
- macOS Keychain
- Windows Credential Manager
- Linux Secret Service/libsecret
- 1Password

Later:

- Doppler
- Infisical
- Bitwarden Secrets Manager
- HashiCorp Vault
- AWS Secrets Manager
- GCP Secret Manager
- Azure Key Vault

## Backend contract

Backends should support:

- validate configuration
- resolve logical secret reference
- return secret only to broker internals
- redact values from errors/logs
- optionally report metadata such as backend type and secret id

## Agent visibility

Agents may see logical capability/resource names. They should not receive raw
secret values.

Open question: how much secret metadata should policy and audit expose?

## Notes

`.env` support is primarily for onboarding, tests, and compatibility. It is not
the strongest security story because agents may be able to read local project
files directly. The security story starts with OS keychains and remote BYO
providers such as 1Password.
