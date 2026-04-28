# MCP reference notes

This file will summarize the MCP protocol references used by the implementation.

Do not paste large third-party docs here. Link to authoritative references and
record the small product-specific decisions this repo relies on.

## References

- Schema reference: <https://modelcontextprotocol.io/specification/2025-11-25/schema>
- Tools reference: <https://modelcontextprotocol.io/specification/draft/server/tools>
- JSON-RPC 2.0: <https://www.jsonrpc.org/specification>

## Local decisions

- `ctxa mcp serve` uses stdio with one JSON-RPC message per line.
- The server advertises only the `tools` capability and sets
  `tools.listChanged` to `false`.
- `tools/list` returns tools in deterministic order.
- `tools/call` uses MCP `CallToolResult` responses. Tool-level failures return
  `isError: true`; malformed JSON-RPC requests use JSON-RPC error objects.
- The initial MCP surface is stateless and does not load local config, secrets,
  policy, approval state, or signing keys.
