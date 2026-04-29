# MCP server

The MCP server is a first-class interface for agents.

## Current surface

`ctxa mcp serve` runs a minimal MCP-compatible stdio JSON-RPC server. It reads
one JSON-RPC message per line from stdin and writes one JSON-RPC response per
line to stdout.

Implemented methods:

- `initialize`
- `ping`
- `tools/list`
- `tools/call`

Implemented tools:

- `capabilities.list`
- `receipts.verify`

`initialize` accepts only protocol version `2025-11-25`. Requests for any other
protocol version fail with a JSON-RPC invalid-params error instead of silently
negotiating unsupported behavior.

`receipts.verify` currently performs structural verification only: it checks
that the receipt parses into the local receipt schema and includes a supported
non-empty `ed25519` signature envelope. Key-based signature verification is
still tracked by the receipt-verification work.

## Initial tools

- `capabilities.list` - implemented
- `receipts.verify` - implemented with structural verification
- `actions.request` - planned
- `http.request` - planned
- `approvals.status` - planned
- `audit.search` - planned

## Tool rule

Do not expose `secrets.get` or equivalent raw secret retrieval. Agents request
actions, not secret values.

## Example exchange

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0.0"}}}
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"authority-broker","title":"Authority Broker","version":"0.1.0"},"instructions":"Request capabilities, not raw secrets. This server exposes only redacted broker metadata and receipt verification helpers."}}
```

Tool list request:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

Tool call request:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capabilities.list","arguments":{}}}
```

## Smoke test

A generic MCP client should be able to:

1. list capabilities
2. verify receipt structure
3. request an allowed fake HTTP action
4. request a risky fake email action
5. observe approval-required state
6. complete action after local approval
7. verify receipt cryptographically

Items 1 and 2 are covered by the current minimal MCP surface. Items 3-7 require
the planned action, approval, and key-based receipt verification tools.
