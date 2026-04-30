#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Run a real-provider ctxa smoke test.

Default backend:
  keychain    Read a GitHub token from `gh auth token`, store it temporarily in
              macOS Keychain, then exercise GitHub through ctxa.

Other backend:
  onepassword Requires CTXA_SMOKE_GITHUB_TOKEN_REF=op://... and `op`.

Environment:
  CTXA_BIN                         ctxa binary to run. Default: ctxa
  CTXA_SMOKE_BACKEND               keychain | onepassword. Default: keychain
  CTXA_SMOKE_OWNER                 GitHub owner. Default: parsed from origin
  CTXA_SMOKE_REPO                  GitHub repo. Default: parsed from origin
  CTXA_SMOKE_HOME                  Existing CTXA_HOME to use. Default: temp dir
  CTXA_SMOKE_KEEP_HOME             Keep generated CTXA_HOME when set to 1
  CTXA_SMOKE_GITHUB_TOKEN_REF      1Password op:// ref for onepassword backend

The script only performs read calls by default. It checks provider execution,
generic HTTPS proxy execution, denied actions, receipt verification, and token
leakage in command output/local ctxa state.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

repo_from_origin() {
  local remote
  remote="$(git remote get-url origin 2>/dev/null || true)"
  if [[ "$remote" =~ ^https://github.com/([^/]+)/([^/.]+)(\.git)?$ ]]; then
    printf '%s/%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$remote" =~ ^git@github.com:([^/]+)/([^/.]+)(\.git)?$ ]]; then
    printf '%s/%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    return 0
  fi
  return 1
}

run() {
  local name="$1"
  shift
  local stdout="$work_dir/$name.stdout"
  local stderr="$work_dir/$name.stderr"
  echo "smoke: $name" >&2
  echo "+ $*" >>"$transcript"
  if ! "$@" >"$stdout" 2>"$stderr"; then
    assert_no_token_leak
    cat "$stderr" >&2
    echo "command failed: $*" >&2
    return 1
  fi
}

run_expect_fail() {
  local name="$1"
  shift
  local stdout="$work_dir/$name.stdout"
  local stderr="$work_dir/$name.stderr"
  echo "smoke: $name" >&2
  echo "+ ! $*" >>"$transcript"
  if "$@" >"$stdout" 2>"$stderr"; then
    assert_no_token_leak
    echo "command unexpectedly succeeded: $*" >&2
    return 1
  fi
}

assert_no_token_leak() {
  if [[ -z "${github_token:-}" ]]; then
    return 0
  fi
  if grep -R -F -n --binary-files=text "$github_token" "$work_dir" "$CTXA_HOME" >/dev/null 2>&1; then
    echo "raw GitHub token was found in smoke output or ctxa local state" >&2
    echo "CTXA_HOME=$CTXA_HOME" >&2
    exit 1
  fi
}

cleanup() {
  local exit_code=$?
  if [[ -n "${keychain_service:-}" && -n "${keychain_account:-}" ]]; then
    security delete-generic-password -s "$keychain_service" -a "$keychain_account" >/dev/null 2>&1 || true
  fi
  if [[ "${CTXA_SMOKE_KEEP_HOME:-0}" != "1" && -n "${created_home:-}" ]]; then
    rm -rf "$created_home"
  fi
  rm -rf "$work_dir"
  exit "$exit_code"
}

require_cmd jq
require_cmd curl

ctxa_bin="${CTXA_BIN:-ctxa}"
require_cmd "$ctxa_bin"

backend="${CTXA_SMOKE_BACKEND:-keychain}"
owner="${CTXA_SMOKE_OWNER:-}"
repo="${CTXA_SMOKE_REPO:-}"

if [[ -z "$owner" || -z "$repo" ]]; then
  owner_repo="$(repo_from_origin || true)"
  if [[ -z "$owner_repo" ]]; then
    echo "set CTXA_SMOKE_OWNER and CTXA_SMOKE_REPO, or run from a GitHub checkout" >&2
    exit 1
  fi
  owner="${owner:-${owner_repo%%/*}}"
  repo="${repo:-${owner_repo#*/}}"
fi

work_dir="$(mktemp -d)"
created_home=""
if [[ -n "${CTXA_SMOKE_HOME:-}" ]]; then
  export CTXA_HOME="$CTXA_SMOKE_HOME"
  mkdir -p "$CTXA_HOME"
else
  created_home="$(mktemp -d)"
  export CTXA_HOME="$created_home/home"
fi
transcript="$work_dir/transcript.log"
: >"$transcript"
trap cleanup EXIT

github_token=""
secret_ref=""

case "$backend" in
  keychain)
    require_cmd gh
    require_cmd security
    github_token="$(gh auth token)"
    if [[ -z "$github_token" ]]; then
      echo "gh auth token returned an empty token" >&2
      exit 1
    fi
    keychain_service="ctxa-smoke-$(date +%s)-$$"
    keychain_account="github-pat"
    security add-generic-password -U -s "$keychain_service" -a "$keychain_account" -w "$github_token" >/dev/null
    secret_ref="$keychain_account"
    run init "$ctxa_bin" init
    cat >"$CTXA_HOME/config.yaml" <<YAML
secret_backend:
  type: os-keychain
  service: $keychain_service
YAML
    ;;
  onepassword)
    require_cmd op
    if [[ -z "${CTXA_SMOKE_GITHUB_TOKEN_REF:-}" ]]; then
      echo "set CTXA_SMOKE_GITHUB_TOKEN_REF to an op:// GitHub token reference" >&2
      exit 1
    fi
    github_token="$(op read "$CTXA_SMOKE_GITHUB_TOKEN_REF")"
    if [[ -z "$github_token" ]]; then
      echo "op read returned an empty token" >&2
      exit 1
    fi
    secret_ref="$CTXA_SMOKE_GITHUB_TOKEN_REF"
    run init "$ctxa_bin" init
    cat >"$CTXA_HOME/config.yaml" <<'YAML'
secret_backend:
  type: one-password
  timeout_ms: 10000
YAML
    ;;
  *)
    echo "unsupported CTXA_SMOKE_BACKEND: $backend" >&2
    exit 1
    ;;
esac

profile="smoke-gh"
resource="github:$owner/$repo"
issues_url="https://api.github.com/repos/$owner/$repo/issues?per_page=1"
blocked_url="https://api.github.com/user"

run profile_create "$ctxa_bin" profile create "$profile" --agent smoke-agent
run provider_add "$ctxa_bin" capability provider add-github --id github --token-ref "$secret_ref"
run grant_create "$ctxa_bin" capability grant create \
  --id github-issues-read \
  --profile "$profile" \
  --provider github \
  --capability github.issues.read \
  --resource "$resource"

run capability_read "$ctxa_bin" capability execute \
  --profile "$profile" \
  --provider github \
  --capability github.issues.read \
  --resource "$resource" \
  --operation '{"state":"open","per_page":1}'
jq -e '.provider_response | type == "array"' "$work_dir/capability_read.stdout" >/dev/null

run_expect_fail denied_create "$ctxa_bin" capability execute \
  --profile "$profile" \
  --provider github \
  --capability github.issues.create \
  --resource "$resource" \
  --payload '{"title":"ctxa smoke should not create this"}'

run_expect_fail invalid_operation "$ctxa_bin" capability execute \
  --profile "$profile" \
  --provider github \
  --capability github.issues.read \
  --resource "$resource" \
  --operation '{"statee":"open"}'

run profile_add_https "$ctxa_bin" profile add-https "$profile" \
  --id github-issues \
  --host api.github.com \
  --secret-ref "$secret_ref" \
  --allow-method GET \
  --path-prefix "/repos/$owner/$repo/issues"

run proxy_allowed "$ctxa_bin" run --profile "$profile" --clean-env -- \
  curl -fsS "$issues_url"
jq -e 'type == "array"' "$work_dir/proxy_allowed.stdout" >/dev/null

run_expect_fail proxy_blocked "$ctxa_bin" run --profile "$profile" --clean-env -- \
  curl -fsS "$blocked_url"

run receipts_list "$ctxa_bin" receipts list --limit 20
receipt_id="$(awk 'NF >= 2 { print $2; exit }' "$work_dir/receipts_list.stdout")"
if [[ -z "$receipt_id" ]]; then
  echo "no receipt id found after smoke run" >&2
  exit 1
fi
run receipt_show "$ctxa_bin" receipts show "$receipt_id"
run receipt_verify "$ctxa_bin" receipts verify "$work_dir/receipt_show.stdout"
run audit_log "$ctxa_bin" log --limit 50

assert_no_token_leak

echo "real provider smoke passed"
echo "backend=$backend"
echo "repo=$owner/$repo"
if [[ "${CTXA_SMOKE_KEEP_HOME:-0}" == "1" || -n "${CTXA_SMOKE_HOME:-}" ]]; then
  echo "ctxa_home=$CTXA_HOME"
else
  echo "ctxa_home=$CTXA_HOME (temporary; removed on exit)"
fi
