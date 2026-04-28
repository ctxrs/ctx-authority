# Security model

## Goal

Constrain how agents use capabilities without handing them durable credentials.

## In scope

- Raw secret redaction.
- Policy enforcement before provider execution.
- Approval-bound actions.
- Payload hash binding.
- Local audit.
- Offline receipt verification.
- Fake-provider security tests.

## Out of scope

- Proving an arbitrary local agent is honest about intent.
- Preventing malware on the same machine from reading local files.
- Protecting secrets after they are intentionally sent to a provider.
- Solving payment, phone, email, or compliance risk before those adapters exist.

## Required launch claims

Only claim what tests prove. For v1, the desired claim is:

> The broker does not expose configured raw secrets to the agent through its
> documented CLI, MCP, audit, receipt, or provider-result surfaces.

Do not claim full endpoint security, enterprise compliance, or regulated
workflow readiness.
