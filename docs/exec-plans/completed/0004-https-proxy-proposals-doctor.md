# Completed plan: HTTPS proxy, proposals, and doctor

## Outcome

`ctxa run` supports common agent traffic that uses HTTPS APIs while preserving
the capability model:

```text
agent process -> HTTPS_PROXY -> ctxa local proxy -> profile rule -> secret backend -> upstream HTTPS API -> audit + receipt
```

## Implemented scope

### Process-scoped HTTPS proxy

- Added an explicit `scheme` field to profile HTTP resources. Existing resources
  default to `http`; `ctxa profile add-https` writes `scheme: https`.
- HTTP bare hosts default to port 80. HTTPS bare hosts default to port 443.
- `ctxa profile add-https` and `profile test` must treat `api.example.com` and
  `api.example.com:443` as the same HTTPS resource; `:80` must not match.
- Support `CONNECT host:port HTTP/1.1`.
- Require proxy authorization before accepting a tunnel.
- Return `200 Connection Established` only after proxy authorization and target
  validation.
- Terminate TLS inside the local proxy with a per-run local CA. The CA private
  key stays in memory. The CA certificate is written to a temporary file for
  child-process trust and removed when `ctxa run` exits.
- Generate leaf certificates per CONNECT host with the host as DNS SAN.
- Inject child trust variables for common clients:
  - `HTTPS_PROXY`
  - `https_proxy`
  - `SSL_CERT_FILE`
  - `REQUESTS_CA_BUNDLE`
  - `CURL_CA_BUNDLE`
  - `NODE_EXTRA_CA_CERTS`
  - `GIT_SSL_CAINFO`
- Do not install a CA into the system trust store.
- Match the decrypted HTTP request by method, CONNECT host, and path prefix.
- Support HTTP/1.1 inside the TLS tunnel. Do not advertise HTTP/2.
- Reject mismatches between CONNECT authority and decrypted absolute-form
  request authority. Origin-form requests use the CONNECT host as authority.
- Resolve the configured secret only after proxy auth, CONNECT target validation,
  TLS handshake, and profile rule matching.
- Strip caller-supplied auth/proxy/hop-by-hop headers.
- Inject broker-managed bearer auth.
- Forward to the upstream HTTPS API with normal upstream certificate validation.
- Do not follow upstream HTTPS redirects inside the broker. Return redirect
  responses to the child so each subsequent request is evaluated as a new profile
  proxy request.
- Do not use ambient proxy environment variables for broker-to-upstream HTTPS
  forwarding.
- Do not enable automatic broker-to-upstream retries.
- Record redacted audit events and signed receipts.

### Proposals

- When an authenticated HTTP or HTTPS request is denied by profile policy, record
  a local `proxy_request_proposal` event. Malformed and unauthenticated requests
  do not create proposals.
- Proposal records must include profile id, agent id, method, host, path, query
  presence, and reason.
- Proposal records must not include raw secrets, request bodies, raw query
  strings, or caller auth headers.
- Implemented command:

```text
ctxa proposals list
```

The command lists redacted proposal events from the local audit log in
newest-first order with `--limit`. It does not mutate policy.

### Doctor

Implemented commands:

```text
ctxa doctor
ctxa doctor --profile <id>
ctxa profile test <id> --url <url> [--method <METHOD>]
```

`doctor` checks local configuration, secret backend construction, CA file
temporary-file writeability, profile validation, and proxy bindability without
exposing secret values. It exits non-zero on failed checks.

`profile test` checks whether a method and URL would match a configured profile
resource. It defaults to `GET`, exits zero when allowed, exits non-zero when
denied, and does not resolve secrets or call the upstream API.

## Design constraints

- No network service dependency.
- No global CA installation.
- No raw secret values in stdout, stderr, audit events, receipts, proposals, or
  docs.
- No browser/runtime-specific assumptions.
- Existing HTTP proxy behavior must continue to work.
- Existing `ctxa profile add-http` remains supported.
- Added `ctxa profile add-https` as an ergonomic alias for HTTPS API resources
  using the same profile resource model.

## Tests

- `ctxa run` injects HTTPS proxy and CA trust env vars.
- `ctxa run` supports a child HTTPS CONNECT denial using the injected proxy and
  CA trust variables.
- `ctxa profile add-https` writes the same resource model as `add-http`.
- HTTPS CONNECT denies missing or invalid proxy auth before secret resolution.
- HTTPS CONNECT rejects mismatches between CONNECT authority and decrypted
  absolute-form request authority before secret resolution.
- HTTPS CONNECT allows a configured request, injects broker bearer auth, forwards
  to a test HTTPS upstream, and records a verifiable receipt.
- HTTPS upstream redirects to disallowed same-host paths and different
  host-port authorities are returned without being followed.
- HTTPS upstream certificate validation failures return a redacted bad gateway
  response.
- HTTPS denial records a redacted proposal without resolving secrets.
- Proposal output does not contain request body, raw query, caller auth, or
  configured secret values.
- `ctxa doctor` succeeds on initialized local state.
- `ctxa profile test` reports allowed and denied profile URL checks.
- Full repository gate passes:

```text
bazel test //:full_suite
```
