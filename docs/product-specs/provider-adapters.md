# Provider adapters

Provider adapters execute normalized action requests using credentials from
secret backends. Run profiles also include a built-in HTTP proxy execution path
for absolute-form `http://` requests.

## Fake-first rule

Every real adapter must have a fake adapter with the same behavior contract.
Default tests use fakes.

## Supported execution surfaces

- fake provider adapter for closed-system action request tests
- local HTTP credential proxy for `ctxa run` profiles

The proxy is not a generic HTTPS interception layer. It handles supported HTTP
proxy requests, strips caller auth/proxy headers, injects broker-managed bearer
auth, and records redacted audit and receipt metadata.

## Adapter contract

Adapter lifecycle:

```text
validate_config
prepare
authorize
execute
reconcile
redact
evidence
```

## Execution rule

Provider execution must happen only after policy allows the action or approval
has been granted for the exact payload hash.

Denied actions must not call the adapter.

For run profiles, secret resolution and upstream forwarding must happen only
after the request passes proxy authorization, host matching, method matching, and
path-prefix matching.
