# Security Policy

`ctx authority` is security-sensitive because it mediates agent access to credentials and capabilities.

## Supported Versions

Supported versions are the latest tagged release and `main` for source builds.

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability.

Send a private report through the GitHub Security Advisory flow for this repository.

Include:

- affected commit or version
- steps to reproduce
- expected behavior
- observed behavior
- whether raw secrets, approvals, receipts, or policy enforcement are involved

## Scope

Security-sensitive areas include run profile enforcement, local proxy authorization, policy evaluation, secret backend resolution, approval binding, audit logging, receipt signing, MCP parsing, and provider execution.
