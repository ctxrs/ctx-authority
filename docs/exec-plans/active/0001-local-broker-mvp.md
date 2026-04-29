# Execution plan: local broker MVP

## Goal

Build a local-first `ctxa` MVP that lets an agent request fake-provider actions
through policy, approval, audit, and signed receipts without requiring real
provider credentials.

## Non-goals

- hosted cloud
- mobile approvals
- real email sending
- phone/SMS/voice
- spending
- physical mail
- enterprise admin

## Milestones

1. Choose implementation stack.
2. Scaffold CLI and test runner.
3. Define config and policy schema.
4. Implement fake secret backend.
5. Implement fake provider adapter.
6. Implement policy decisions: allow, deny, require approval.
7. Implement fail-closed approval handling plus internal approval-provider tests.
8. Implement audit log.
9. Implement receipt signing and verification.
10. Implement MCP server.
11. Add full closed-system acceptance tests.
12. Add quickstart docs.

## Acceptance criteria

The MVP is ready when:

- `ctxa init` creates local config.
- `ctxa policy trust --id default --path policy.yaml` pins a policy hash.
- `ctxa agent create demo --policy default` creates an executable trusted agent
  profile.
- allowed fake action succeeds.
- denied fake action does not reach provider.
- risky fake action asks for approval and fails closed without a configured
  human approval provider.
- internal runtime tests cover approved and rejected approval outcomes.
- receipt verifies offline.
- tampered receipt fails verification.
- raw fake secret value does not appear in logs, receipts, stdout, or stderr.
- MCP smoke tests cover implemented metadata and receipt-shape tools; MCP action
  execution is a planned follow-up.
