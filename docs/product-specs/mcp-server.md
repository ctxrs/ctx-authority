# MCP server

The MCP server is a first-class interface for agents.

## Supported surface

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

`initialize` requires protocol version `2025-11-25`. Requests with a missing or
different protocol version fail with a JSON-RPC invalid-params error instead of
silently negotiating unsupported behavior.

`receipts.verify` performs structural verification only: it checks that the
receipt parses into the local receipt schema and includes a supported non-empty
`ed25519` signature envelope. Use `ctxa receipts verify` for cryptographic local
receipt verification.

## Supported MCP tools

- `capabilities.list` - implemented
- `receipts.verify` - implemented with structural verification

## Tool rule

Do not expose `secrets.get` or equivalent raw secret retrieval. Agents request
actions, not secret values.

## Example exchange

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"example-client","version":"0.1.0"}}}
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"ctxa","title":"ctx authority","version":"0.1.0"},"instructions":"Request capabilities, not raw secrets. This server exposes only redacted broker metadata and receipt verification helpers."}}
```

Tool list request:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

Tool call request:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capabilities.list","arguments":{}}}
```

## MCP acceptance behavior

The MCP surface supports:

1. list capabilities
2. verify receipt structure

Action execution, approval state, audit search, and cryptographic receipt
verification are not available over MCP.
