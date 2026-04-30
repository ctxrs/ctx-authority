# Provider Capabilities

## Outcome

Implemented local bring-your-own-token provider capability adapters so an agent
can exercise named provider authorities such as `github.issues.read` or
`google.gmail.drafts.create` without receiving the underlying provider token.

The broker now issues receipts that identify the exact capability, resource,
grant chain, credential reference hash, provider request id, and adapter
metadata.

## Delivered

- Provider-capability model separate from `SecretBackend`.
- GitHub, Google, and Microsoft capability adapters.
- GitHub App installation-token minting from a locally supplied app JWT.
- Attenuable provider capability grants.
- CLI surface under `ctxa capability`.
- MCP tools for profile-bound capability grant inspection, delegation, and
  execution.
- Fake-provider integration tests for provider routing, grant enforcement, and
  token redaction.
- Public docs for the local, bring-your-own-provider-token workflow.

## Boundaries

`SecretBackend` resolves existing credential references. Capability adapters use
those credentials to issue an internal `CapabilityLease`, then execute a granted
provider operation. This does not implement hosted OAuth consent, refresh-token
custody, browser login, or hosted account linking.

MCP capability mutation and execution require the server process to be bound to
a profile through `CTXA_PROFILE` or `CTXA_MCP_PROFILE`.

## Resource Grammar

- GitHub repo: `github:owner/repo`
- Gmail mailbox: `google:gmail`
- Google Calendar: `google:calendar/<calendar-id>`
- Google Drive file: `google:drive/<file-id>`
- Google Docs document: `google:docs/<document-id>`
- Microsoft Outlook mailbox: `microsoft:outlook`
- Microsoft Calendar: `microsoft:calendar`
- Microsoft Drive item: `microsoft:drive/<item-id>`

The v1 resource subset rule is exact-match. Grants that need different resource
types should be separate grants.

## Verification

Planned and executed gates:

- `cargo fmt --check`
- `git diff --check`
- `scripts/bazel/leak_scan.sh`
- `scripts/bazel/cargo_test.sh`
- `scripts/bazel/cargo_clippy_check.sh`
- `scripts/bazel/cli_smoke_test.sh`
- `bazel test //:full_suite`
