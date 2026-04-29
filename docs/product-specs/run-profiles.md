# Run profiles

## User

A technical user who wants to run a local agent with scoped access to selected HTTP resources.

## Problem

Agents often need API credentials to do useful work. Putting those credentials in the agent environment gives the process more authority than the human intended and makes accidental disclosure easy.

## Core behavior

`ctxa run --profile <id> -- <command>` starts a local loopback HTTP proxy, injects proxy environment variables into the child process, and runs the command. Requests sent through the proxy are allowed only when they match the selected profile.

The child receives:

- `HTTP_PROXY`
- `http_proxy`
- `CTXA_PROXY_URL`
- `CTXA_PROXY_TOKEN`
- `CTXA_PROFILE`

Existing `ALL_PROXY`, HTTPS proxy vars, and `NO_PROXY` are removed or neutralized for the child so supported HTTP traffic uses the profile proxy.

## Profile config

Profiles live in `config.yaml`:

```yaml
secret_backend:
  type: one-password

profiles:
  - id: github-reader
    agent: my-agent
    env:
      GITHUB_API_BASE: http://api.github.com
    http_resources:
      - id: github-issues
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
ctxa profile add-http github-reader \
  --id github-issues \
  --host api.github.com \
  --secret-ref op://example-vault/github-token/token \
  --allow-method GET \
  --path-prefix /repos/example/repo/issues
ctxa run --profile github-reader -- my-agent
```

Repeated `profile add-http` with the same resource id replaces that resource.

## Proxy authorization

Every proxy run has a random local proxy token. The generated proxy URL includes proxy credentials, and requests must present matching proxy auth before any secret is resolved.

The proxy accepts:

- `Proxy-Authorization: Bearer <token>`
- basic proxy auth generated from the injected proxy URL

Unauthenticated local requests receive `407` and do not resolve secrets.

## Request matching

The proxy supports absolute-form `http://` requests. `CONNECT` and HTTPS interception are not supported.

Allowed requests must match:

- configured host after lowercase/default-port normalization
- configured method
- configured path prefix at a segment boundary

The proxy rejects malformed or ambiguous targets, userinfo, fragments, unsupported IPv6 syntax, dot segments, encoded traversal, encoded slashes, encoded backslashes, repeated slashes, and unsafe query syntax.

Query strings may be forwarded to the upstream API, but raw query strings are not written to audit events or receipts.

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
- The proxy handles HTTP requests, not HTTPS interception.
- Request headers, request bodies, upstream responses, and concurrent requests are capped.
- Request bodies must use `Content-Length`; chunked request bodies are rejected.
