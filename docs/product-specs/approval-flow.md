# Approval flow

Approval is required when policy returns `require_approval`.

Approvals are not the only way to authorize actions. The product should support
both durable scoped grants and one-off approvals.

## Grants vs approvals

Grant:

- durable or time-bounded permission configured ahead of time
- used for routine low-risk actions
- examples: "agent demo can read GitHub issues" or "agent demo can call GET on
  api.example.com under this path"

Approval:

- one-off human decision for a specific action request
- bound to exact canonical action hash and policy hash/version
- used for risky, novel, or externally visible actions
- examples: "send this specific email" or "make this specific purchase request"

## Local approval

The public CLI fails closed for approval-required actions unless a trusted
approval provider is configured by the broker runtime. Test approval providers
exist only inside the Rust test harness.

A human approval prompt should present enough information for a specific
decision:

```text
Agent demo wants to perform email.send through fake-mailgun.
To: external@example.com
Subject: Demo
Action hash: sha256:...

Approve? [y/N]
```

Approval-required actions must not be auto-approved through agent-controlled CLI
flags, MCP arguments, or environment variables.

## Binding

Approval must bind to:

- action request id
- canonical action hash
- policy hash/version
- approver id
- expiration time

If any bound field changes, execution must fail.

## Expiration

Approvals should expire quickly by default. Grants should have explicit scope.
The v1 policy schema does not accept `expires_at`; a grant must be narrow enough
to be safe without an expiry.

Example durable grant:

```yaml
grants:
  - id: github_issues_read
    agent: demo
    capability: http.request
    resource: github-main
    allow:
      methods: [GET]
      hosts: [api.github.com]
      path_prefixes:
        - /repos/example-org/example-repo/issues
```

Example of a time-bounded shape that is not accepted:

```yaml
grants:
  - id: vendor_lookup_window
    agent: demo
    capability: http.request
    resource: vendor-api
    expires_at: "2000-01-01T00:00:00Z"
    allow:
      methods: [GET]
      hosts: [api.vendor.example]
      path_prefixes:
        - /vendors
```

## Audit

Record:

- approval requested
- approval granted
- approval rejected
- approval failed or unavailable
- approval expired
- execution attempted
- execution skipped because approval failed
