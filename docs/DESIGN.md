# Design

The product should feel like a serious local security/devtool:

- fast setup
- explicit policy
- boring defaults
- clear denial reasons
- copy-pasteable examples
- no magical hidden cloud dependency
- no surprise telemetry
- no raw secret exposure

The command surface should be short and memorable:

```bash
ctxa init
ctxa agent create personal
ctxa policy edit personal
ctxa run --agent personal -- openclaw
ctxa approve
ctxa log
ctxa receipts verify receipt.json
ctxa mcp install
```

Prefer precise language:

- "capability" over "secret"
- "action request" over "tool call" when policy applies
- "receipt" over "log" when the record is signed/verifiable
- "approval" only when a human or configured approver actually approved
