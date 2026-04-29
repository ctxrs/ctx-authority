# Policy schema

Policy files are human-editable YAML.

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
        - /repos/example-org/example-repo/issues
  - id: fake_mail_send_requires_approval
    agent: demo
    capability: email.send
    resource: fake-mailgun
    allow:
      recipient_domains: [example.com]
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

## Supported v1 capabilities

- `http.request`
- `email.send`

Unsupported capability names in grants are invalid policy. Unsupported
capability names in action requests must deny and must not reach a provider.

## Grants

Policies support durable scoped grants so humans do not have to approve every
routine action.

A grant is safe only when it is specific:

- named agent
- named capability
- named resource
- narrow method/host/path/recipient constraints
- optional expiry
- optional rate limit

Broad grants are avoided in examples.
For v1, `http.request` grants are invalid unless `methods`, `hosts`, and
`path_prefixes` are all present and non-empty. Omitted HTTP dimensions do not
act as implicit wildcards. The `http.request` operation object may contain only
`method`, `host`, and `path`.
HTTP grants must not specify email-only allow dimensions such as
`recipient_domains`.

For v1, `email.send` grants are invalid unless `recipient_domains` is present
and non-empty. Recipient matching is exact and case-insensitive on the domain
portion of a single bare `operation.to` email address. `email.send` operation
objects may contain only `to` and `subject`. `http.request` and `email.send`
payload objects may be omitted/null or contain only `body`. Display-name
syntax, cc/bcc fields, subdomain wildcards, query-string fields, and
multi-recipient payloads are not accepted by the v1 schema and must deny.
Email grants must not specify HTTP-only allow dimensions such as `methods`,
`hosts`, or `path_prefixes`.

HTTP path constraints must be safe to compare without relying on provider
normalization:

- `path_prefixes` entries must be absolute paths and must not be empty.
- `path_prefixes` entries must not be `/` and must not end in `/`; write the
  subtree root without a trailing slash.
- Path prefixes and requested paths must not contain `.` or `..` segments.
- Percent-encoded dot segments such as `%2e%2e` and double-encoded variants are
  unsafe and must deny or fail validation.
- Backslashes, repeated slashes, encoded slashes, query strings, fragments, and
  control characters are invalid in HTTP paths.
- Prefix matching is exact or subtree-only: `/issues` matches `/issues/1`, but
  not `/issues-admin`.

## Default behavior

- Unsupported policy version: invalid policy, deny.
- Unknown agent: deny.
- Unknown capability: deny.
- Unknown resource: deny.
- Invalid policy: deny.
- Unknown policy fields: invalid policy, deny.
- Evaluation error: deny.
- Conflicting allow and deny: deny.
