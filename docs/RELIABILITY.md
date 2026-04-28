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

## Build and test reliability

- Bazel wrapper targets should resolve the workspace root in normal shell usage
  and under Bazel runfiles.
- Cargo build output must stay outside the repository through `.cargo/config.toml`
  and the Bazel wrapper environment.
- Wrapper scripts should use locked dependencies where Cargo supports it.
- The CLI smoke test should capture stdout and stderr for each command and scan
  generated local state for the fake secret sentinel.
- The leak scan should use high-confidence credential patterns so public docs
  and fake fixtures do not create noisy failures.
