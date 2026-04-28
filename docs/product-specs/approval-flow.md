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

The first implementation can use a CLI prompt:

```text
Agent demo wants to perform email.send through fake-mailgun.
To: external@example.com
Subject: Demo
Action hash: sha256:...

Approve? [y/N]
```

For deterministic local tests, `ctxa action request` may also be run with
`--approval approve` or `--approval reject`. The same behavior can be selected
with `CTXA_APPROVAL_MODE=approve` or `CTXA_APPROVAL_MODE=reject`.

If no approval mode or approval UI is configured, approval-required actions must
fail closed. Test auto-approval is only available through the explicit flag or
environment variable above.

If there is a local daemon, approval can happen from another terminal:

```bash
ctxa approvals watch
ctxa approvals approve appr_123
ctxa approvals reject appr_123
```

A TUI can be added if the CLI queue becomes hard to use:

```bash
ctxa approvals
```

The TUI should show pending approvals, payload summary, policy reason, expiry,
and approve/reject controls.

## Binding

Approval must bind to:

- action request id
- canonical action hash
- policy hash/version
- approver id
- expiration time

If any bound field changes, execution must fail.

## Expiration

Approvals should expire quickly by default. Candidate local default: 10 minutes.

Grants should have explicit scope and optional expiry. A grant without an expiry
must still be narrow enough to be safe.

Example durable grant:

```yaml
grants:
  - id: github_issues_read
    capability: http.request
    resource: github-main
    allow:
      methods: [GET]
      hosts: [api.github.com]
      path_prefixes:
        - /repos/ctx-rs/authority-broker/issues
```

Example time-bounded grant:

```yaml
grants:
  - id: vendor_lookup_window
    capability: http.request
    resource: vendor-api
    expires_at: "2026-04-28T23:00:00Z"
    allow:
      methods: [GET]
      hosts: [api.vendor.example]
```

## Audit

Record:

- approval requested
- approval granted
- approval rejected
- approval expired
- execution attempted
- execution skipped because approval failed
