# Agent skill

The repository ships a runtime-agnostic skill/instruction pack for agents.

## Goal

Any agent should be able to learn how to use `ctxa` safely without receiving
raw secrets or unrelated implementation details.

## Contents

The skill teaches:

- what `ctxa` is
- when to request a capability
- how to call the CLI
- how to use the MCP tools
- how to handle allow, deny, and approval-required responses
- how to avoid leaking secrets into prompts, logs, files, or error reports
- how to verify receipts

## Current MCP guidance

The skill describes `ctxa mcp serve` as a stdio MCP server with a minimal tool
surface:

- `capabilities.list` lists currently exposed MCP tools and planned broker
  capabilities.
- `receipts.verify` accepts either `receipt` as an object or `receipt_json` as a
  string and performs structural receipt verification.

The skill must not claim MCP support for action execution or approval polling
until `actions.request`, `http.request`, and `approvals.status` are implemented.

## Runtime-specific docs

Separate setup docs can explain how to expose the skill to:

- Codex
- Claude Code
- OpenClaw
- Cursor
- generic MCP clients

The skill itself should stay runtime-agnostic.
