# Security

This project is security-sensitive because it mediates agent access to
credentials and capabilities.

## Current status

Pre-implementation planning scaffold. Do not use this repository as a security
boundary until implementation and security review exist.

## Security goals

- Agents can request actions without receiving raw durable credentials.
- Policy decisions are explicit and auditable.
- Risky actions can require approval.
- Approvals are bound to exact payload hashes.
- Receipts are tamper-detectable.
- Logs, errors, audit events, and receipts redact secrets.

## Non-goals

The local broker cannot prove that an arbitrary local agent is honest about its
intent. It can constrain what credentials and provider actions the agent can use
through this broker.

## Reporting vulnerabilities

Security contact details will be added before public release.
