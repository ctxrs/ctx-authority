#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/env.sh"
cd "$(ctxa_workspace_root)"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export CTXA_HOME="$tmp/home"

all_output="$tmp/all-command-output.txt"
: > "$all_output"

cargo build --quiet --locked --bin ctxa
ctxa_codesign_debug_binary_if_needed
ctxa_bin="$CARGO_TARGET_DIR/debug/ctxa"

run_ctxa() {
  local name="$1"
  shift
  local stdout="$tmp/$name.stdout"
  local stderr="$tmp/$name.stderr"

  if ! "$ctxa_bin" "$@" >"$stdout" 2>"$stderr"; then
    cat "$stdout" "$stderr" >> "$all_output"
    if grep -R -n --binary-files=text 'fake-secret-value' "$tmp" "$CTXA_HOME" >/dev/null 2>&1; then
      echo "fake secret leaked while running ctxa $*" >&2
    fi
    cat "$stderr" >&2
    return 1
  fi

  cat "$stdout" "$stderr" >> "$all_output"
}

run_ctxa init init
run_ctxa setup_runtime setup runtime codex --profile codex
run_ctxa profile_create profile create github-reader --agent demo-agent
run_ctxa profile_create_main profile create main-agent --agent main-agent
run_ctxa profile_create_worker profile create worker-agent --agent worker-agent
run_ctxa profile_add_https profile add-https github-reader --id github-issues --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo/issues
run_ctxa grant_create grants create-https --id github-root --profile main-agent --host api.github.com --secret-ref op://example-vault/github-token/token --allow-method GET --path-prefix /repos/example/repo --delegable --max-depth 2
run_ctxa grant_delegate grants delegate --from github-root --id worker-issues --profile worker-agent --allow-method GET --path-prefix /repos/example/repo/issues
run_ctxa grant_list grants list --profile worker-agent
run_ctxa grant_show grants show worker-issues
run_ctxa capability_provider capability provider add-github --id github --token-ref op://example-vault/github-token/token
run_ctxa capability_grant_create capability grant create --id github-cap-root --profile main-agent --provider github --capability github.issues.read --resource github:example/repo --delegable --max-depth 2
run_ctxa capability_grant_delegate capability grant delegate --from github-cap-root --id github-cap-worker --profile worker-agent --capability github.issues.read --resource github:example/repo
run_ctxa capability_grant_list capability grant list --profile worker-agent
run_ctxa capability_grant_show capability grant show github-cap-worker
run_ctxa profile_test profile test github-reader --method GET --url https://api.github.com/repos/example/repo/issues
run_ctxa profile_test_grant profile test worker-agent --method GET --url https://api.github.com/repos/example/repo/issues/1
run_ctxa doctor_profile doctor --profile github-reader
run_ctxa ca_status ca status
run_ctxa proposals_list proposals list
run_ctxa receipts_list_empty receipts list
run_ctxa policy_trust policy trust --id default --path tests/fixtures/demo-policy.yaml
run_ctxa agent_create agent create demo --policy default
run_ctxa policy_check policy check --policy tests/fixtures/demo-policy.yaml --file tests/fixtures/demo-action.json
cp "$tmp/policy_check.stdout" "$tmp/decision.json"
grep -q '"decision": "allow"' "$tmp/decision.json"
run_ctxa action_request action request --file tests/fixtures/demo-action.json
cp "$tmp/action_request.stdout" "$tmp/receipt.json"
grep -q '"receipt_version": "authority.receipt.v1"' "$tmp/receipt.json"
run_ctxa receipt_verify receipts verify "$tmp/receipt.json"
run_ctxa receipts_list receipts list
run_ctxa audit_log log --limit 20

if grep -R -n --binary-files=text 'fake-secret-value' "$tmp" "$CTXA_HOME" >/dev/null 2>&1; then
  echo "fake secret leaked through ctxa init/agent/policy/action output or local state" >&2
  exit 1
fi
