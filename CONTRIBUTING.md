# Contributing

Contributions should keep the broker small, explicit, and testable. Start with
the relevant spec, add focused tests, and keep behavior aligned with the public
architecture.

## Before coding

Read:

- [AGENTS.md](AGENTS.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [docs/product-specs/index.md](docs/product-specs/index.md)
- [docs/SECURITY.md](docs/SECURITY.md)

## Expectations

- Keep changes small and testable.
- Prefer fake providers over real external services.
- Do not add credentials or non-public examples.
- Update specs when behavior changes.
- Add tests for security-sensitive behavior.

## Security-sensitive changes

Changes touching policy, secrets, approvals, logging, receipts, or provider
execution need tests proving that secrets are not leaked and denied actions do
not execute.
