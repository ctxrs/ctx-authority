# Policy schema

Initial policy format should be human-editable YAML.

Example:

```yaml
version: 1
grants:
  - id: fake_http_read
    agent: demo
    capability: http.request
    resource: fake-github
    allow:
      methods: [GET]
      hosts: [api.fake-github.local]
      path_prefixes:
        - /repos/ctx-rs/authority-broker/issues
  - id: fake_mail_send_requires_approval
    agent: demo
    capability: email.send
    resource: fake-mailgun
    allow: {}
    require_approval: true
```

## Decisions

Policy decision values:

- `allow`
- `deny`
- `require_approval`

Policy evaluation must return matched rule ids or explanations.
`require_approval: true` on a matching grant changes the decision from `allow`
to `require_approval`; the action can run only after a local approval record is
issued for the same action payload hash and policy hash.

## Required v1 rule dimensions

- agent id
- capability
- resource
- HTTP method
- host
- path prefix
- recipient domain for email-like fake actions
- approval required
- deny rule

## Grants

Policies should support durable scoped grants so humans do not have to approve
every routine action.

A grant is safe only when it is specific:

- named agent
- named capability
- named resource
- narrow method/host/path/recipient constraints
- optional expiry
- optional rate limit

Broad grants should be avoided in examples.

## Default behavior

- Unknown agent: deny.
- Unknown capability: deny.
- Unknown resource: deny.
- Invalid policy: deny.
- Unknown policy fields: invalid policy, deny.
- Evaluation error: deny.
- Conflicting allow and deny: deny.
