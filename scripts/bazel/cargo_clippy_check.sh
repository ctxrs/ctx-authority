#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/env.sh"
cd "$(authority_broker_workspace_root)"
cargo clippy --all-targets --all-features --locked -- -D warnings
