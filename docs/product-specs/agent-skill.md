# Agent skill

The repository ships a runtime-agnostic skill/instruction pack for agents.

## Goal

Any agent should be able to learn how to use `ctxa` safely without receiving
raw secrets or unrelated implementation details.

## Contents

The skill teaches:

- what `ctxa` is
- when to request a capability
- how to use profile-provided proxy environment variables
- how to call the CLI
- how to use the MCP tools
- how to handle allow, deny, and approval-required responses
- how to avoid leaking secrets into prompts, logs, files, or error reports
- how to verify receipts

## MCP guidance

The skill describes `ctxa mcp serve` as a stdio MCP server with a minimal tool
surface:

- `capabilities.list` lists available MCP tools and broker capabilities.
- `receipts.verify` accepts either `receipt` as an object or `receipt_json` as a
  string and performs structural receipt verification.

MCP support is limited to the tools listed above.

## Run profile guidance

When an agent is started with `ctxa run`, it should use `HTTP_PROXY`,
`HTTPS_PROXY`, or `CTXA_PROXY_URL` for supported API calls and should not ask
the human for the backing token. The proxy owns credential injection and
receipt generation.

The skill itself should stay runtime-agnostic.
