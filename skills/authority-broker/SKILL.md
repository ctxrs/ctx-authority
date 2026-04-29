# authority-broker

Use `ctxa` when you need to perform an action that may require credentials,
approval, or an audit trail.

Do not ask the human for raw secrets. Do not write secrets into prompts, files,
logs, or command output.

## Core rule

Request capabilities, not secrets.

## Common commands

```bash
ctxa action request --file <action.json>
ctxa policy check --policy <policy.yaml> --file <action.json>
ctxa log
ctxa receipts verify <receipt.json>
ctxa mcp serve
```

`ctxa action request` uses the human-configured trusted policy and agent profile
from local broker config. Do not supply your own policy path for execution.

## MCP tools

When connected through MCP, use `capabilities.list` to inspect the currently
available local tools.

Use `receipts.verify` to check receipt shape through MCP. Pass either a receipt
object as `receipt` or a JSON string as `receipt_json`. This MCP tool currently
checks that the receipt parses and has a supported non-empty ed25519 signature
envelope; it does not yet perform key-based signature verification.

## Decision handling

If `ctxa` allows the action, continue with the result.

If `ctxa` denies the action, stop and report the denial reason. Do not retry by
asking for raw credentials.

If `ctxa` says approval is required, wait for approval or tell the human what
approval is needed. Do not change the payload after approval. A changed payload
requires a new approval.

## Receipt handling

When an action returns a receipt, keep the receipt path or id with the task
result. Use receipt verification when asked to prove what happened.
