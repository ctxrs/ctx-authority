# AGENTS.md

This is a public open-source repository. Treat every file, commit, issue, test,
and comment as publishable.

## What this repo is

This repository contains `ctxa`, the local CLI for `ctx authority`. It lets
agents request actions without receiving raw durable credentials.

Core loop:

```text
agent requests action
broker evaluates policy
broker asks for approval if required
broker executes through provider adapter
broker writes audit event
broker emits signed receipt
```

## Repository boundary

Use only materials included in this repository unless maintainers provide
sanitized context. Do not add secrets, API keys, tokens, credentials, cookies,
session files, customer data, or provider account details. Use fake providers
and fixtures by default.

## Start here

Read these files before implementation:

1. [ARCHITECTURE.md](ARCHITECTURE.md)
2. [docs/product-specs/index.md](docs/product-specs/index.md)
3. [docs/design-docs/core-beliefs.md](docs/design-docs/core-beliefs.md)
4. [docs/SECURITY.md](docs/SECURITY.md)
5. [docs/product-specs/local-broker.md](docs/product-specs/local-broker.md)

Use the deeper docs as the source of truth. Keep this file short.

## Engineering rules

- For local builds and tests, run through Bazel targets or source
  `scripts/bazel/env.sh` before direct Cargo commands. That keeps Cargo output
  and `sccache` state outside the repository.
- Default to closed-system tests with fake providers.
- Do not require internet access for the core test suite.
- Do not expose raw secrets in stdout, stderr, logs, audit events, receipts, MCP
  responses, or error messages.
- Denied actions must not call provider adapters.
- Approval must bind to payload hash and policy version.
- Changed payload after approval must require a new approval.
- Receipt verification must fail after tampering.
- Policy parse or evaluation ambiguity must default closed.
- Update specs and tests when behavior changes.

## Documentation rules

If a task adds or changes behavior, update the corresponding product spec. If a
task introduces a new architectural decision, update [ARCHITECTURE.md](ARCHITECTURE.md)
or a design doc.

Avoid large monolithic docs. Prefer short indexed docs with links.

## Release hygiene

Before preparing a public release, run secret scanning and source review. At a
minimum, scan for secrets, credentials, and unintended references to non-public
material.
