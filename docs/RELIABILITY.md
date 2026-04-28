# Reliability

The local broker should fail closed.

## Principles

- If policy cannot be parsed, deny.
- If policy cannot be evaluated, deny.
- If approval state is ambiguous, deny.
- If receipt signing fails, mark execution as failed unless a future explicit
  unsafe mode exists.
- If provider execution status is unknown, record an unknown state and require
  reconciliation before retry when idempotency matters.
- If a secret backend fails, do not fall back to weaker sources unless policy
  explicitly allows it.

## Deterministic tests

The test suite should use:

- fake providers
- fake secret backend
- fake approval provider
- deterministic clock
- deterministic signing key
- deterministic filesystem temp dirs

The default test suite should be offline.
