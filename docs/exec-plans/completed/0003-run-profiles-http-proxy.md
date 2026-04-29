# Completed plan: run profiles and HTTP credential proxy

## Outcome

`ctxa run` now starts an agent command inside a named profile, provides a
loopback HTTP proxy for allowed profile resources, resolves credentials only
inside the broker, and records redacted audit events plus signed receipt
metadata.

## Completed work

- Added `profiles` config with scoped HTTP resource rules.
- Added `ctxa profile create`, `ctxa profile add-http`, and `ctxa run`.
- Added a per-run loopback HTTP proxy with proxy authorization before secret
  resolution.
- Added bearer-token injection for allowed absolute-form `http://` requests.
- Added redacted audit events and signed proxy receipt metadata.
- Added tests for profile parsing, CLI behavior, proxy authorization, denials,
  header stripping, URL rejection, receipt verification, and leak scanning.

## Verification

The completed gate is:

```text
bazel test //:full_suite
```
