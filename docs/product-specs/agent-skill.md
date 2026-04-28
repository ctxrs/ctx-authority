# Agent skill

The repository should ship a runtime-agnostic skill/instruction pack for agents.

## Goal

Any agent should be able to learn how to use `ctxa` safely without receiving
raw secrets or private implementation context.

## Contents

The skill should teach:

- what `ctxa` is
- when to request a capability
- how to call the CLI
- how to use the MCP tools
- how to handle allow, deny, and approval-required responses
- how to avoid leaking secrets into prompts, logs, files, or error reports
- how to verify receipts

## Runtime-specific docs

Separate setup docs can explain how to expose the skill to:

- Codex
- Claude Code
- OpenClaw
- Cursor
- generic MCP clients

The skill itself should stay runtime-agnostic.
