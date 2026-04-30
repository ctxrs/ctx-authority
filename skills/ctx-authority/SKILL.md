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
ctxa grants list [--profile <profile-id>]
ctxa grants show <grant-id>
ctxa grants delegate --from <grant-id> --id <child-grant-id> --profile <profile-id> --allow-method <METHOD> --path-prefix <path>
ctxa capability grant list [--profile <profile-id>] [--provider <provider-id>]
ctxa capability grant show <grant-id>
ctxa capability grant delegate --from <grant-id> --id <child-grant-id> --profile <profile-id> --capability <capability> --resource <resource>
ctxa capability execute --profile <profile-id> --provider <provider-id> --capability <capability> --resource <resource> [--operation <json>] [--payload <json>]
ctxa proposals list
ctxa proposals show <proposal-id>
ctxa action request --file <action.json>
ctxa policy check --policy <policy.yaml> --file <action.json>
ctxa log
ctxa receipts list
ctxa receipts show <receipt-id>
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

MCP capability grant delegation and capability execution are bound to the server
process profile through `CTXA_PROFILE` or `CTXA_MCP_PROFILE`. Do not request a
different profile through MCP.

## Decision handling

If `ctxa` allows the action, continue with the result.

If `ctxa` denies the action, stop and report the denial reason. Do not retry by
asking for raw credentials.

If a `ctxa run` API request is denied, tell the human that they can inspect
redacted proposals with `ctxa proposals list`. Do not ask for the backing token
or attempt the request outside the proxy.

If you hold a delegable grant and need to hand a narrower capability to another
profile, use `ctxa grants delegate`. The child grant must stay within the
parent grant's method and path scope. Do not ask for or copy the backing secret
reference.

If you hold a delegable provider capability grant, use
`ctxa capability grant delegate`. The child grant must stay within the parent
provider, capability list, resource list, and delegation depth.

When you need a supported provider operation such as `github.issues.read`, use
`ctxa capability execute`. The command returns the provider response and a signed
receipt. Do not ask for the provider token and do not try to recreate the API
call outside `ctxa`.

If `ctxa` says approval is required, wait for approval or tell the human what
approval is needed. Do not change the payload after approval. A changed payload
requires a new approval.

## Receipt handling

When an action returns a receipt, keep the receipt path or id with the task
result. Use receipt verification when asked to prove what happened.
