# ctx authority

Use `ctxa` when you need to perform an action that may require credentials,
approval, or an audit trail.

Do not ask the human for raw secrets. Do not write secrets into prompts, files,
logs, or command output.

## Core rule

Request capabilities, not secrets.

## Common commands

```bash
ctxa run --profile <profile-id> -- <agent-or-tool-command>
ctxa profile test <profile-id> --url <url> [--method <METHOD>]
ctxa doctor --profile <profile-id>
ctxa proposals list
ctxa action request --file <action.json>
ctxa policy check --policy <policy.yaml> --file <action.json>
ctxa log
ctxa receipts verify <receipt.json>
ctxa mcp serve
```

If you are already running inside `ctxa run`, use the provided `HTTP_PROXY`,
`HTTPS_PROXY`, or `CTXA_PROXY_URL` for supported API calls. Do not ask for the
underlying API token. Do not replace the proxy-managed `Authorization` header.

`ctxa action request` uses the human-configured trusted policy and agent profile
from local broker config. Do not supply your own policy path for execution.

## MCP tools

When connected through MCP, use `capabilities.list` to inspect the currently
available local tools.

Use `receipts.verify` to check receipt shape through MCP. Pass either a receipt
object as `receipt` or a JSON string as `receipt_json`. For cryptographic
receipt verification, use `ctxa receipts verify`; MCP receipt verification
checks structure only.

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
