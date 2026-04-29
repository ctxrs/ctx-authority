# Project goals

`ctx authority` should be understandable in one sentence:

> Give agents capabilities, not secrets.

The local broker is for technical users who run agent tools and want those tools
to use credentials without exposing durable raw secrets to the agent process.

## Core jobs

- Let an agent use real credentials without putting those credentials in a
  prompt, environment, or agent-readable config file.
- Deny ambiguous requests by default.
- Require approval for policy-marked actions.
- Record local audit events.
- Emit signed receipts that can be inspected and verified.

The public scope is the implemented local broker behavior and its limits.
