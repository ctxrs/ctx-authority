#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/env.sh"
cd "$(ctxa_workspace_root)"

"$script_dir/cargo_fmt_check.sh"
"$script_dir/cargo_clippy_check.sh"
"$script_dir/cargo_test.sh"
"$script_dir/cli_smoke_test.sh"
"$script_dir/leak_scan.sh"
