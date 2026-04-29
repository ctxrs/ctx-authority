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
ctxa profile create github-reader --agent my-agent
ctxa profile add-http github-reader --id github-issues --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo/issues
ctxa run --profile github-reader -- my-agent
ctxa agent create personal
ctxa policy trust --id personal --path policy.yaml
ctxa action request --file action.json
ctxa log
ctxa receipts verify receipt.json
ctxa mcp serve
```

Prefer precise language:

- "capability" over "secret"
- "profile" for the launch-time authority given to a process
- "action request" over "tool call" when policy applies
- "receipt" over "log" when the record is signed/verifiable
- "approval" only when a human or configured approver actually approved
