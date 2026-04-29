# authority-broker

Run agents with real capabilities without giving them raw secrets.

`authority-broker` is the open-source local edge component for `ctx authority`.
It is intended to sit between an AI agent and the credentials/capabilities that
agent wants to use.

The agent requests an action. The broker checks policy, asks for approval when
needed, executes through a provider adapter, records an audit event, and emits a
signed receipt.

```text
agent -> authority-broker -> policy -> approval -> provider -> receipt
```

## Status

Early local MVP implementation. The CLI, fake-provider closed-system tests,
pluggable secret-backend interface, local audit log, signed receipts, minimal
MCP metadata server, agent skill, Bazel gates, and leak scan are in place.
Real provider adapters and hosted services are intentionally not included yet.

## Target MVP

- CLI binary: `ctxa`
- Local daemon later.
- Minimal MCP server.
- Agent-agnostic skill/instruction pack.
- Local YAML policies.
- Trusted local policy attachment to agent profiles.
- Pluggable secret backends.
  - fake backend
  - `.env`
  - macOS Keychain
  - Windows Credential Manager
  - Linux Secret Service/libsecret
  - 1Password
- Provider/action adapter interface.
- Local approvals.
- Local SQLite audit log.
- Signed action receipts.
- Offline receipt verification.
- Fake providers and deterministic tests.

No signup should be required for local mode.

## Non-goals for the first release

- Hosted cloud service.
- Hosted email.
- Phone/SMS/voice.
- Spending cards.
- Physical mail.
- Browser automation.
- VM/runtime hosting.
- Enterprise SSO.
- Full dashboard.

## Repository map

- [AGENTS.md](AGENTS.md): instructions for coding agents working in this public
  repo.
- [ARCHITECTURE.md](ARCHITECTURE.md): top-level architecture and boundaries.
- [docs/product-specs/](docs/product-specs/): product behavior and acceptance
  criteria.
- [skills/authority-broker/](skills/authority-broker/): agent-agnostic usage
  instructions for agents.
- [docs/design-docs/](docs/design-docs/): product and engineering principles.
- [docs/exec-plans/](docs/exec-plans/): active and completed implementation
  plans.
- [docs/SECURITY.md](docs/SECURITY.md): security model and threat notes.
- [docs/references/agent-first-repo-structure.md](docs/references/agent-first-repo-structure.md):
  source inspiration for the agent-first documentation layout.

## Public boundary

This is intended to be a public open-source repository. Do not add private ctx
internal plans, private transcripts, personal workflows, customer data, provider
credentials, or proprietary implementation details.
