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
- how to treat denied requests as proposals instead of asking for raw secrets
- how to call the CLI
- how to use the MCP tools
- how to handle allow, deny, and approval-required responses
- how to avoid leaking secrets into prompts, logs, files, or error reports
- how to verify receipts

## MCP guidance

The skill describes `ctxa mcp serve` as a stdio MCP server with these local
tools:

- `capabilities.list` lists available MCP tools and broker capabilities.
- `receipts.verify` accepts either `receipt` as an object or `receipt_json` as a
  string and verifies the receipt against the local ctx authority signing key.
- `capability.grants.list` and `capability.grants.show` inspect grants held by
  the bound profile.
- `capability.grants.delegate` can create a mechanically narrower child grant.
- `capability.execute` can execute granted provider capabilities.

Grant mutation and execution require `CTXA_PROFILE` or `CTXA_MCP_PROFILE` and
are constrained to the bound profile.

## Run profile guidance

When an agent is started with `ctxa run`, it should use `HTTP_PROXY`,
`HTTPS_PROXY`, or `CTXA_PROXY_URL` for supported API calls and should not ask
the human for the backing token. The proxy owns credential injection and
receipt generation.

If a profile request is denied, the agent should report that a proposal may be
available through `ctxa proposals list`. The agent must not ask for the raw
token or bypass the proxy.

The skill itself should stay runtime-agnostic.
