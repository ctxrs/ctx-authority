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
- `capability.grants.list`
- `capability.grants.show`
- `capability.grants.delegate`
- `capability.execute`

`initialize` requires protocol version `2025-11-25`. Requests with a missing or
different protocol version fail with a JSON-RPC invalid-params error instead of
silently negotiating unsupported behavior.

`receipts.verify` performs local cryptographic verification. It parses the
receipt, loads the local ctx authority signing key, checks the receipt key id,
and verifies the Ed25519 signature.

## Supported MCP tools

- `capabilities.list` - implemented
- `receipts.verify` - implemented with local Ed25519 verification
- `capability.grants.list` - implemented
- `capability.grants.show` - implemented
- `capability.grants.delegate` - implemented; mutates local config by creating a narrower child grant from the bound profile's parent grant
- `capability.execute` - implemented; executes only when the bound profile has a matching local capability grant

## Tool rule

Do not expose `secrets.get` or equivalent raw secret retrieval. Agents request
actions, not secret values.

## Example exchange

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"example-client","version":"client-version"}}}
```

Response:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"ctxa","title":"ctx authority","version":"current-version"},"instructions":"Request capabilities, not raw secrets. This server exposes redacted broker metadata, local receipt verification, profile-bound capability grant delegation, and granted provider capability execution."}}
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
2. verify locally signed receipts
3. list and show provider capability grants
4. delegate mechanically narrower provider capability grants
5. execute granted provider capabilities

Approval state and audit search are not available over MCP. Capability mutation
and execution require the MCP server process to be bound to a profile with
`CTXA_PROFILE` or `CTXA_MCP_PROFILE`. Capability execution is available only for
configured local provider adapters and local capability grants held by that
bound profile. It returns the same redacted execution envelope as the CLI.
