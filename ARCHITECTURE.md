# Architecture

`ctxa` is the local capability broker for `ctx authority`.

It is useful by itself in offline/local mode. This repository implements the
local CLI, policy, audit, receipt, secret-backend, and provider-adapter
boundaries.

## Boundaries

Implemented surfaces:

- local CLI
- MCP server for metadata and structural receipt verification
- agent-agnostic skill/instruction pack
- local policies
- fail-closed approval handling
- local audit log
- signed receipts
- secret backend interface
- provider/action adapter interface
- profile-scoped HTTP and HTTPS proxy for `ctxa run`
- fake providers and deterministic tests

## Control path

```text
Agent runtime
  -> ctxa CLI / MCP server / local daemon
  -> ActionRequest
  -> Policy evaluation
  -> Approval if required
  -> Provider adapter execution
  -> Audit event
  -> Signed receipt
```

## Agent skill

The repo includes a runtime-agnostic skill/instruction pack. It teaches agents
how to use `ctxa` and the MCP server safely, without embedding assumptions about
specific agent runtimes.

The skill is documentation plus examples, not a privileged execution surface.

## Core primitives

- `AgentProfile`: named local agent identity and policy attachment.
- `Principal`: local human or organization principal.
- `Capability`: named action surface such as `http.request` or `email.send`.
- `ResourceHandle`: logical resource such as `github-main` or `mailgun-demo`.
- `Policy`: rules that allow, deny, or require approval.
- `ActionRequest`: normalized action proposed by an agent.
- `ApprovalRequest`: human approval prompt bound to canonical action hash.
- `ActionExecution`: provider execution result.
- `EvidenceBlob`: optional redacted evidence metadata.
- `Receipt`: signed, tamper-detectable action record.
- `SecretBackend`: source of durable credentials.
- `ProviderAdapter`: executor that uses credentials without exposing them to the
  agent.
- `ProfileResource`: HTTP or HTTPS resource rule for a launched agent process.
- `AuditEvent`: local event record.
- `IdempotencyKey`: duplicate-execution guard.

## Default decision flow

1. Parse and validate action request.
2. Resolve agent profile and policy.
3. Evaluate policy.
4. Deny immediately if denied.
5. Ask for approval if required.
6. Refuse execution if approval is rejected, expired, or payload-mismatched.
7. Resolve provider adapter and retrieve required secret inside the broker.
8. Execute provider action.
9. Redact provider result.
10. Write audit event.
11. Emit signed receipt.

## Secret handling

Agents should receive capabilities, not raw durable secrets.

The broker may read secrets from local backends, but raw secret values must not
be returned to the agent, included in MCP responses, written to audit logs,
embedded in receipts, or printed in errors.

## Receipts

Receipts are the bridge between local execution and later verification. The
local receipt is verifiable offline and includes:

- receipt version
- receipt id
- agent id
- action type
- resource
- canonical action hash
- policy hash/version
- approval reference when applicable
- execution status
- provider result summary
- issued timestamp
- signature

Receipts should not include raw secrets.

## Fake-first provider model

Every external provider must have a fake adapter. The default test suite should
not depend on real provider credentials, network access, or human approval.
