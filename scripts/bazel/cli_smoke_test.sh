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

run_ctxa() {
  local name="$1"
  shift
  local stdout="$tmp/$name.stdout"
  local stderr="$tmp/$name.stderr"

  if ! cargo run --quiet --locked --bin ctxa -- "$@" >"$stdout" 2>"$stderr"; then
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
run_ctxa policy_trust policy trust --id default --path tests/fixtures/demo-policy.yaml
run_ctxa agent_create agent create demo --policy default
run_ctxa policy_check policy check --policy tests/fixtures/demo-policy.yaml --file tests/fixtures/demo-action.json
cp "$tmp/policy_check.stdout" "$tmp/decision.json"
grep -q '"decision": "allow"' "$tmp/decision.json"
run_ctxa action_request action request --file tests/fixtures/demo-action.json
cp "$tmp/action_request.stdout" "$tmp/receipt.json"
grep -q '"receipt_version": "authority.receipt.v1"' "$tmp/receipt.json"
run_ctxa receipt_verify receipts verify "$tmp/receipt.json"
run_ctxa audit_log log --limit 20

if grep -R -n --binary-files=text 'fake-secret-value' "$tmp" "$CTXA_HOME" >/dev/null 2>&1; then
  echo "fake secret leaked through ctxa init/agent/policy/action output or local state" >&2
  exit 1
fi
