# Agent-first repo structure

This repo's documentation layout is inspired by OpenAI's "Harness engineering:
leveraging Codex in an agent-first world" post.

Reference: https://openai.com/index/harness-engineering/

Key practices adapted here:

- Keep `AGENTS.md` short and use it as a map.
- Put product specs, architecture, reliability, and security docs in-repo.
- Treat execution plans as versioned artifacts.
- Make fake providers and closed-system tests first-class.
- Encode acceptance criteria mechanically instead of relying on prompt memory.
- When an agent struggles, improve the repo's tools, docs, tests, or fixtures.

This repo should not copy the exact OpenAI structure blindly. It should use the
same principle: repository-local knowledge is the system of record for agents.
