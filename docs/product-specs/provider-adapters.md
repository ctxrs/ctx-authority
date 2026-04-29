# Provider adapters

Provider adapters execute normalized actions using credentials from secret
backends.

## Fake-first rule

Every real adapter must have a fake adapter with the same behavior contract.
Default tests use fakes.

## Current adapters

- fake HTTP
- fake GitHub
- fake Mailgun

Planned:

- generic HTTP adapter

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
