# authority-broker

Use `ctxa` when you need to perform an action that may require credentials,
approval, or an audit trail.

Do not ask the human for raw secrets. Do not write secrets into prompts, files,
logs, or command output.

## Core rule

Request capabilities, not secrets.

## Common commands

```bash
ctxa action request --agent <agent-id> --file <action.json>
ctxa policy check --agent <agent-id> --file <action.json>
ctxa log
ctxa receipts verify <receipt.json>
```

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
