# Product sense

The user should understand the product in under one minute:

> Give agents capabilities, not secrets.

The first user is a technical user running local agent tools.

The first job to be done:

> I want my agent to use real credentials without pasting those credentials into
> a prompt, environment, or tool config that the agent can read.

The second job:

> I want risky agent actions to ask me first and leave an audit trail.

The third job:

> I want receipts I can inspect and verify, with a format that can be synced or
> shared later.

Avoid broad claims in the product UI. The first release should not promise to
solve enterprise IAM, payments, phone, email, or compliance. It should solve
local capability brokering well.
