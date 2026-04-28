# Architecture

`authority-broker` is a local capability broker for agents.

It is designed to be useful by itself in offline/local mode and to become the
open-source edge/client for `ctx authority` cloud later.

## Boundaries

In scope:

- local CLI
- local daemon
- MCP server
- agent-agnostic skill/instruction pack
- local policies
- local approvals
- local audit log
- signed receipts
- secret backend interface
- provider/action adapter interface
- fake providers and deterministic tests

Out of scope for this repo's first release:

- hosted cloud control plane
- mobile approvals
- hosted email
- phone/SMS/voice
- cards/spending
- physical mail
- enterprise SSO/admin
- public receipt verification service

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
Codex, Claude, OpenClaw, or any private runtime.

The skill is documentation plus examples, not a privileged execution surface.

## Core primitives

- `AgentProfile`: named local agent identity and policy attachment.
- `Principal`: local human or future organization principal.
- `Capability`: named action surface such as `http.request` or `email.send`.
- `ResourceHandle`: logical resource such as `github-main` or `mailgun-demo`.
- `Policy`: rules that allow, deny, or require approval.
- `ActionRequest`: normalized action proposed by an agent.
- `ApprovalRequest`: human approval prompt bound to payload hash.
- `ActionExecution`: provider execution result.
- `EvidenceBlob`: optional redacted evidence metadata.
- `Receipt`: signed, tamper-detectable action record.
- `SecretBackend`: source of durable credentials.
- `ProviderAdapter`: executor that uses credentials without exposing them to the
  agent.
- `AuditEvent`: local event record.
- `IdempotencyKey`: duplicate-execution guard.

## Default decision flow

1. Parse and validate action request.
2. Resolve agent profile and policy.
3. Evaluate policy.
4. Deny immediately if denied.
5. Ask for approval if required.
6. Refuse execution if approval is rejected, expired, or payload-mismatched.
7. Resolve provider adapter and retrieve required secret internally.
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

Receipts are the bridge from local utility to future verification. The local
receipt should be verifiable offline and should include:

- receipt version
- receipt id
- agent id
- action type
- resource
- payload hash
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
