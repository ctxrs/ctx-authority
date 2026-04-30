# Architecture

`ctxa` is the local capability broker for `ctx authority`.

It is useful by itself in offline/local mode. This repository implements the
local CLI, policy, audit, receipt, secret-backend, and provider-adapter
boundaries.

## Boundaries

Implemented surfaces:

- local CLI
- MCP server for metadata, structural receipt verification, profile-bound
  capability grant delegation, and granted capability execution
- agent-agnostic skill/instruction pack
- local policies
- fail-closed approval handling
- local audit log
- signed receipts
- secret backend interface
- provider/action adapter interface
- provider capability adapters for local BYO provider tokens
- profile-scoped HTTP and HTTPS proxy for `ctxa run`
- profile-held HTTP grants and grant-backed proxy matching
- profile-held provider capability grants and delegation
- fake providers and deterministic tests

## Control path

```text
Agent runtime
  -> ctxa CLI / MCP server
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
- `CapabilityIssuer`: provider adapter that issues an internal lease from a
  locally configured provider credential and executes a named provider
  capability.
- `CapabilityLease`: internal short-lived provider authority. It is not printed,
  stored in audit events, or returned through MCP.
- `ProfileResource`: HTTP or HTTPS resource rule for a launched agent process.
- `Grant`: attenuable HTTP authority that can be delegated without copying the
  root secret reference into child grants.
- `CapabilityGrant`: attenuable provider authority scoped by profile, provider,
  capability list, and typed resource list.
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
