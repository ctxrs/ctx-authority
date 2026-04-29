# Infisical reference notes

Infisical is a likely secret backend and an adjacent product in agent
credential brokering.

Treat Infisical as a secret backend integration. The broker's product value is
policy, approval, action execution, and receipts across many backends and
providers.

Potential integration shapes:

- CLI-backed local development backend for users who already authenticate the
  Infisical CLI
- API-backed backend for server-side broker deployments
- secret sync or injected environment workflows when the broker does not fetch
  directly at action time

Implementation requirements:

- never log secret values, raw command output, or provider error payloads that
  may contain values
- keep provider account identifiers out of fixtures and tests
- use deterministic fake stores in tests unless a separate integration test is
  explicitly opted in
- model Infisical references as backend-scoped references, not as broker-native
  policy identities

Public references:

- Infisical CLI overview: https://infisical.com/docs/documentation/getting-started/cli
- Infisical secrets CLI commands: https://infisical.com/docs/cli/commands/secrets
- Infisical secret delivery concepts: https://infisical.com/docs/documentation/platform/secrets-mgmt/concepts/secrets-delivery
