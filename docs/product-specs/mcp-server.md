# MCP server

The MCP server is a first-class interface for agents.

## Initial tools

- `capabilities.list`
- `actions.request`
- `http.request`
- `approvals.status`
- `audit.search`
- `receipts.verify`

## Tool rule

Do not expose `secrets.get` or equivalent raw secret retrieval. Agents request
actions, not secret values.

## Smoke test

A generic MCP client should be able to:

1. list capabilities
2. request an allowed fake HTTP action
3. request a risky fake email action
4. observe approval-required state
5. complete action after local approval
6. verify receipt
