# Run profiles

## User

A technical user who wants to run a local agent with scoped access to selected HTTP resources.

## Problem

Agents often need API credentials to do useful work. Putting those credentials in the agent environment gives the process more authority than the human intended and makes accidental disclosure easy.

## Core behavior

`ctxa run --profile <id> -- <command>` starts a local loopback profile proxy, injects proxy environment variables into the child process, and runs the command. Requests sent through the proxy are allowed only when they match the selected profile.

The child receives:

- `HTTP_PROXY`
- `http_proxy`
- `HTTPS_PROXY`
- `https_proxy`
- `SSL_CERT_FILE`
- `REQUESTS_CA_BUNDLE`
- `CURL_CA_BUNDLE`
- `NODE_EXTRA_CA_CERTS`
- `GIT_SSL_CAINFO`
- `CTXA_PROXY_URL`
- `CTXA_PROXY_TOKEN`
- `CTXA_PROFILE`

Existing `ALL_PROXY` and `NO_PROXY` values are removed or neutralized for the child so supported traffic uses the profile proxy.

## Profile config

Profiles live in `config.yaml`:

```yaml
secret_backend:
  type: one-password

profiles:
  - id: github-reader
    agent: my-agent
    env:
      GITHUB_API_BASE: https://api.github.com
    http_resources:
      - id: github-issues
        scheme: https
        host: api.github.com
        secret_ref: op://example-vault/github-token/token
        auth:
          type: bearer
        allow:
          methods: [GET]
          path_prefixes: [/repos/example/repo/issues]
```

`env` values are non-secret hints for the child. Secret values are resolved only inside the broker.

## CLI

```bash
ctxa profile create github-reader --agent my-agent
ctxa profile add-https github-reader \
  --id github-issues \
  --host api.github.com \
  --secret-ref op://example-vault/github-token/token \
  --allow-method GET \
  --path-prefix /repos/example/repo/issues
ctxa profile test github-reader --method GET --url https://api.github.com/repos/example/repo/issues
ctxa doctor --profile github-reader
ctxa run --profile github-reader -- my-agent
```

Repeated `profile add-http` or `profile add-https` with the same resource id replaces that resource.

## Proxy authorization

Every proxy run has a random local proxy token. The generated proxy URL includes proxy credentials, and requests must present matching proxy auth before any secret is resolved.

The proxy accepts:

- `Proxy-Authorization: Bearer <token>`
- basic proxy auth generated from the injected proxy URL

Unauthenticated local requests receive `407` and do not resolve secrets.

## HTTPS trust

For HTTPS resources, `ctxa run` handles `CONNECT host:port HTTP/1.1` and
terminates TLS locally with a per-run CA. The CA private key stays in memory.
The CA certificate is written to a temporary file only so the child process can
trust the proxy through the injected trust variables. `ctxa` does not install a
CA into the system trust store.

The proxy accepts HTTP/1.1 inside the tunnel and does not advertise HTTP/2.
Absolute-form HTTPS targets inside the tunnel must match the CONNECT authority.
Origin-form requests use the CONNECT authority.

When forwarding HTTPS requests upstream, the broker does not follow upstream
redirects. Redirect responses are returned to the child process so any follow-up
request must pass through profile matching as a new request. Upstream forwarding
also ignores ambient proxy environment variables and does not enable automatic
request retries.

## Request matching

Allowed requests must match:

- configured scheme
- configured host after lowercase/default-port normalization
- configured method
- configured path prefix at a segment boundary

The proxy rejects malformed or ambiguous targets, userinfo, fragments, unsupported IPv6 syntax, dot segments, encoded traversal, encoded slashes, encoded backslashes, repeated slashes, and unsafe query syntax.

Query strings may be forwarded to the upstream API, but raw query strings are not written to audit events or receipts.

## Proposals

When an authenticated request is denied because no profile resource matches,
the proxy records a redacted `proxy_request_proposal` audit event. Proposal
events include profile id, agent id, method, canonical host, path, whether a
query was present, and denial reason.

Proposal events do not include raw secrets, request bodies, raw query strings,
or caller auth headers.

```bash
ctxa proposals list
ctxa proposals show <proposal-id>
ctxa proposals apply <proposal-id> --secret-ref <ref>
ctxa proposals dismiss <proposal-id>
```

Proposal application creates a new profile resource by default. It requires a
human-supplied `--secret-ref`, never resolves that reference, and fails on
resource-id collision unless `--replace` is explicit. Applied and dismissed
proposals are hidden from default `list` output and visible with `--all`.

The default applied path prefix is the proposed path. Path-prefix matching uses
the same segment-boundary rules as manually configured profile resources.

## Header handling

Before forwarding, the proxy strips caller-supplied auth, proxy, and hop-by-hop headers, then injects:

```text
Authorization: Bearer <resolved-secret>
```

The upstream `Host` header is generated from the canonical target host, not from the caller-supplied `Host` header.

## Audit and receipts

Allowed proxy requests write a signed local receipt to the audit log under `proxy_request_receipt`.

The receipt records:

- profile id as principal
- agent id from the profile, or the profile id when unset
- `http.request`
- resource id
- method, canonical host, and path
- query hash when a query is present
- profile/resource rule hash as `policy_hash`
- redacted proxy execution metadata

Denied, malformed, unauthenticated, and upstream-failed requests write redacted audit events and do not contain resolved secret values.

## Limits

- This is not a process sandbox.
- HTTPS support is process-scoped to the launched child process and depends on clients honoring standard proxy and CA environment variables.
- The proxy supports HTTP/1.1 proxy traffic.
- Request headers, request bodies, upstream responses, and concurrent requests are capped.
- Request bodies must use `Content-Length`; chunked request bodies are rejected.
