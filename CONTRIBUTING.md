# Contributing

This repository is pre-implementation. Contributions should start with specs,
fixtures, tests, or narrowly scoped implementation that follows the public
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
- Do not add credentials or private examples.
- Update specs when behavior changes.
- Add tests for security-sensitive behavior.

## Security-sensitive changes

Changes touching policy, secrets, approvals, logging, receipts, or provider
execution need tests proving that secrets are not leaked and denied actions do
not execute.
