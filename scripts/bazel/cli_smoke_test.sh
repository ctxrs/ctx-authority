#!/usr/bin/env bash
set -euo pipefail
cd "${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
source scripts/bazel/env.sh

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export CTXA_HOME="$tmp/home"

cargo run --quiet --bin ctxa -- init
cargo run --quiet --bin ctxa -- agent create demo
cargo run --quiet --bin ctxa -- policy check --policy tests/fixtures/demo-policy.yaml --file tests/fixtures/demo-action.json > "$tmp/decision.json"
grep -q '"decision": "allow"' "$tmp/decision.json"
cargo run --quiet --bin ctxa -- action request --policy tests/fixtures/demo-policy.yaml --file tests/fixtures/demo-action.json > "$tmp/receipt.json"
grep -q '"receipt_version": "authority.receipt.v1"' "$tmp/receipt.json"
! grep -q 'fake-secret-value' "$tmp/receipt.json"
