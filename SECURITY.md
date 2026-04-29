# Security Policy

`ctx authority` is security-sensitive because it mediates agent access to credentials and capabilities.

## Supported Versions

This repository currently publishes source from the `main` branch. Until tagged releases exist, please test against `main` before reporting an issue.

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability.

Send a private report to the maintainers through the repository security advisory flow once the GitHub repository is published. If that is not available, contact the project maintainers directly.

Include:

- affected commit or version
- steps to reproduce
- expected behavior
- observed behavior
- whether raw secrets, approvals, receipts, or policy enforcement are involved

## Scope

Security-sensitive areas include policy evaluation, secret backend resolution, approval binding, audit logging, receipt signing, MCP parsing, and provider execution.
