# Provider adapters

Provider adapters let an agent exercise a named provider capability without
receiving the underlying provider token. The current model is local and
bring-your-own-token: `SecretBackend` resolves an existing credential reference,
and the adapter uses it internally to call the provider API.

## Model

Secret backends and provider adapters are separate:

- `SecretBackend` resolves durable local credential references.
- `CapabilityIssuer` turns provider auth into an internal `CapabilityLease`.
- `CapabilityLease` is held only inside the broker execution path.
- `CapabilityReceipt` metadata is emitted through the signed receipt envelope.

Provider adapters must not print, store, or return raw provider tokens.

## Supported providers

GitHub:

- auth: bearer token, or GitHub App installation token minted from a locally
  supplied app JWT
- resource: `github:owner/repo`
- capabilities:
  - `github.issues.read`
  - `github.issues.create`
  - `github.issues.comment`
  - `github.prs.read`

Google:

- auth: bearer token from the configured secret backend
- default API base: `https://www.googleapis.com`; Google Docs capabilities use
  `https://docs.googleapis.com` when the provider uses that default base
- resources:
  - `google:gmail`
  - `google:calendar/<calendar-id>`
  - `google:drive/<file-id>`
  - `google:docs/<document-id>`
- capabilities:
  - `google.gmail.messages.read`
  - `google.gmail.drafts.create`
  - `google.gmail.drafts.send`
  - `google.calendar.events.read`
  - `google.calendar.events.create`
  - `google.drive.files.read`
  - `google.drive.files.update`
  - `google.docs.documents.read`
  - `google.docs.documents.update`

Microsoft Graph:

- auth: bearer token from the configured secret backend
- resources:
  - `microsoft:outlook`
  - `microsoft:calendar`
  - `microsoft:drive/<item-id>`
- capabilities:
  - `microsoft.outlook.messages.read`
  - `microsoft.outlook.drafts.create`
  - `microsoft.outlook.messages.send`
  - `microsoft.calendar.events.read`
  - `microsoft.calendar.events.create`
  - `microsoft.drive.files.read`
  - `microsoft.drive.files.update`

## Capability grants

Capability grants are profile-held authority for provider adapters.

Root grants bind:

- profile
- subject
- provider id
- sorted capability list
- sorted resource list
- delegation policy
- optional exact-match constraints for top-level operation and payload fields

Child grants must be mechanically less than or equal to the parent:

- same provider
- capability subset
- resource subset
- any parent operation/payload constraints preserved exactly
- lower remaining delegation depth

The resource subset rule is exact-match in this version. Grants that need
different resource types should be separate grants. Constraint matching is a
small first-class attenuation primitive, not a full policy language: it checks
configured top-level JSON fields for exact equality before provider execution.

## CLI examples

Configure a provider:

```sh
ctxa capability provider add-github \
  --id github \
  --token-ref op://example-vault/github-token/token
```

Create a root grant:

```sh
ctxa capability grant create \
  --id github-root \
  --profile main-agent \
  --provider github \
  --capability github.issues.read \
  --capability github.issues.create \
  --resource github:example-org/example-repo \
  --delegable \
  --max-depth 2
```

Delegate a narrower child grant:

```sh
ctxa capability grant delegate \
  --from github-root \
  --id github-reader \
  --profile worker-agent \
  --capability github.issues.read \
  --resource github:example-org/example-repo
```

Execute a granted capability:

```sh
ctxa capability execute \
  --profile worker-agent \
  --provider github \
  --capability github.issues.read \
  --resource github:example-org/example-repo \
  --operation '{"state":"open"}'
```

## Receipt rule

Capability execution receipts bind:

- holder profile and subject
- provider id and provider kind
- matched grant id and grant chain
- credential reference hash
- adapter version
- capability name
- resource id
- operation and payload hash
- provider status and request id

Provider response bodies are returned to the caller but are not stored in the
receipt result by default.

## Execution rule

Provider execution must happen only after a matching capability grant is found
and the provider operation is locally planned. Denied actions and locally invalid
operation objects must not resolve provider credentials or call the adapter.
Operation objects fail closed when they contain keys that the selected
capability does not support. Provider requests ignore ambient proxy environment
variables, do not follow redirects, use a finite request timeout, cap response
bodies, and preserve any path prefix configured in `api_base` for gateways such
as GitHub Enterprise.

If provider execution fails after a lease is issued, the broker records an
`ambiguous` signed receipt best-effort because a side-effecting provider request
may have reached the upstream service before the local failure surfaced. When an
upstream status or provider request id is known, the receipt includes it.

All tests use local fake provider servers. The default test suite must not
depend on real provider credentials, external provider network access, or human
approval.
