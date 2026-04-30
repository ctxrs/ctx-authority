# Completed plan: CLI-backed secret backends

## Outcome

`ctxa` supports additional local secret backends that resolve credentials through
existing provider CLIs or encrypted local files. These adapters keep raw secret
values inside the broker execution path and use the user's existing provider
authentication state.

## Implemented scope

- Added command-backed resolver infrastructure with no shell execution.
- Added command timeouts and generic provider errors.
- Preserved exact JSON string values for JSON-backed providers.
- Kept plain stdout handling compatible with CLIs that print one terminal line
  ending.
- Added first-class backends for Bitwarden Secrets Manager, Doppler, Infisical,
  HashiCorp Vault, AWS Secrets Manager, AWS SSM Parameter Store, GCP Secret
  Manager, Azure Key Vault, and SOPS.
- Added a trusted local command backend for local integrations that do not yet
  have a compiled adapter.

## Safety properties

- Backends reject unsupported reference syntax before invoking provider CLIs.
- Provider command stdout, stderr, references, and arguments are not included in
  errors.
- Provider CLIs are invoked with explicit argv values, not shell strings.
- Closed-system tests use fake executable scripts and do not require real
  provider accounts or network access.

## Boundary

These are read-only secret resolvers. Provider-native token issuance and scoped
credential minting are capability adapter work because they create new authority
and need separate policy and receipt semantics.
