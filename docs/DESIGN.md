# Design

The product should feel like a reliable local security tool:

- fast setup
- explicit policy
- predictable defaults
- clear denial reasons
- copy-pasteable examples
- no magical hidden cloud dependency
- no surprise telemetry
- no raw secret exposure

The command surface should be short and memorable:

```bash
ctxa init
ctxa setup runtime codex --profile github-reader
ctxa profile create github-reader --agent my-agent
ctxa profile add-https github-reader --id github-issues --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo/issues
ctxa grants create-https --id github-root --profile main-agent --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo --delegable --max-depth 2
ctxa grants delegate --from github-root --id github-issues --profile worker-agent --allow-method GET --path-prefix /repos/example/repo/issues
ctxa grants show github-issues
ctxa profile test github-reader --url https://api.github.com/repos/example/repo/issues
ctxa run --profile github-reader -- my-agent
ctxa proposals list
ctxa proposals apply <proposal-id> --secret-ref op://example-vault/github-token/token
ctxa agent create personal
ctxa policy trust --id personal --path policy.yaml
ctxa action request --file action.json
ctxa log
ctxa receipts list
ctxa receipts show <receipt-id>
ctxa receipts verify receipt.json
ctxa mcp serve
```

Prefer precise language:

- "capability" over "secret"
- "profile" for the launch-time authority given to a process
- "grant" for an attenuable unit of authority that can be delegated
- "action request" over "tool call" when policy applies
- "receipt" over "log" when the record is signed/verifiable
- "approval" only when a human or configured approver actually approved
