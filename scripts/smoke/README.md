# Real Provider Smoke Tests

These scripts exercise `ctxa` against real providers with disposable local
state. They are intentionally outside the default test suite because they use
live credentials and network calls.

## GitHub Smoke

Default mode uses the local GitHub CLI session, stores the token temporarily in
macOS Keychain, and tests both provider capabilities and the generic HTTPS
profile proxy:

```sh
scripts/smoke/real_provider_smoke.sh
```

The script defaults to the repository from `git remote get-url origin`. Override
the target repo when needed:

```sh
CTXA_SMOKE_OWNER=example-org \
CTXA_SMOKE_REPO=example-repo \
scripts/smoke/real_provider_smoke.sh
```

Pass criteria:

- GitHub issue reads succeed through `ctxa capability execute`.
- The same read succeeds through `ctxa run` and the HTTPS profile proxy.
- A write capability without a matching grant is denied.
- An invalid operation object fails before provider execution.
- At least one receipt can be shown and verified.
- The raw GitHub token does not appear in command output or local `ctxa` state.

## 1Password Backend Smoke

If `op` is installed and signed in, use an `op://` reference instead of macOS
Keychain:

```sh
CTXA_SMOKE_BACKEND=onepassword \
CTXA_SMOKE_GITHUB_TOKEN_REF='op://Personal/ctxa-smoke-github-pat/password' \
scripts/smoke/real_provider_smoke.sh
```

Use the vault and field name from the actual 1Password item. A standard
1Password Password item is usually addressable through the `password` field.

## Options

- `CTXA_BIN`: ctxa binary to run. Defaults to `ctxa`.
- `CTXA_SMOKE_BACKEND`: `keychain` or `onepassword`.
- `CTXA_SMOKE_OWNER`: GitHub owner.
- `CTXA_SMOKE_REPO`: GitHub repo.
- `CTXA_SMOKE_HOME`: existing `CTXA_HOME` to use.
- `CTXA_SMOKE_KEEP_HOME=1`: keep generated local state after the run.
- `CTXA_SMOKE_GITHUB_TOKEN_REF`: 1Password reference for onepassword mode.

Use low-scope, disposable provider credentials whenever possible.
