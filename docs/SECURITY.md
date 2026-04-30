# Security model

## Goal

Constrain how agents use capabilities without handing them durable credentials.

## In scope

- Raw secret redaction.
- Policy enforcement before provider execution.
- Profile enforcement before proxy credential injection.
- Per-run local proxy authorization before secret resolution.
- Process-scoped HTTPS proxying for launched child processes.
- Per-run local CA generation without system trust-store installation.
- Approval-bound actions.
- Canonical action-hash binding.
- Local audit.
- Offline receipt verification.
- Fake-provider security tests.
- Proxy tests for auth stripping, deny-before-secret-resolution, HTTPS forwarding, and receipt verification.

## Out of scope

- Proving an arbitrary local agent is honest about intent.
- Preventing malware on the same machine from reading local files.
- Protecting secrets after they are intentionally sent to a provider.
- Sandboxing a child process launched by `ctxa run`.
- Removing authority an already-running local agent has outside `ctxa`.
- System-wide TLS interception or persistent local CA installation.
- Solving risks for capability domains outside this local broker.

## Security guarantees

> The broker does not expose configured raw secrets to the agent through its
> documented CLI, MCP, audit, receipt, or provider-result surfaces.

For run profiles, the supported claim is narrower:

> For supported profile proxy requests, `ctxa` resolves credentials only after
> proxy authorization and profile matching, forwards only a small request-header
> allowlist, injects broker-managed bearer auth, and keeps raw secret values out
> of local audit and receipt output.

For supported HTTPS profile resources, this guarantee applies inside a
process-scoped `CONNECT` tunnel created for the launched child process. The
per-run CA private key remains in memory, and only the CA certificate is exposed
to the child through temporary trust configuration.

Host-mode `ctxa run` inherits the operator environment by default, matching
normal local process-launcher behavior. Use `--clean-env` with explicit
`--inherit-env` keys when the launched process should receive only a minimal
baseline environment plus profile/proxy variables.

Hand-written profile resources default to HTTPS when the `scheme` field is
omitted. Use `ctxa profile add-http` or `ctxa grants create-http` only for
explicit local or plaintext integrations.

The SQLite audit log is local mutable storage. `ctxa` tightens local file
permissions on Unix and fails on malformed audit JSON, but signed receipts are
the durable evidence format.

These guarantees are limited to the documented local broker surfaces and do not
make claims about endpoint hardening, enterprise compliance, or regulated
workflow readiness.
