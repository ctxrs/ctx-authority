#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/env.sh"
cd "$(authority_broker_workspace_root)"

patterns=(
  '-----BEGIN (RSA |DSA |EC |OPENSSH |)?PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'gh[pousr]_[A-Za-z0-9_]{30,}'
  'github_pat_[A-Za-z0-9_]{40,}'
  'glpat-[A-Za-z0-9_-]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{20,}'
  'sk-[A-Za-z0-9]{32,}'
  '(api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|password)[[:space:]]*[:=][[:space:]]*["'\'']?[A-Za-z0-9_./+=:-]{16,}'
)

scan_status=1
if command -v rg >/dev/null 2>&1; then
  rg -n --hidden --glob '!target/**' --glob '!bazel-*/**' --glob '!.git/**' --glob '!.local/**' --glob '!*.log' --glob '!*.sqlite' --glob '!*.sqlite3' --regexp "$(IFS='|'; echo "${patterns[*]}")" . && scan_status=0
else
  grep -REIn --exclude='*.log' --exclude='*.sqlite' --exclude='*.sqlite3' --exclude-dir='.git' --exclude-dir='.local' --exclude-dir='target' --exclude-dir='bazel-bin' --exclude-dir='bazel-out' --exclude-dir='bazel-testlogs' "$(IFS='|'; echo "${patterns[*]}")" . && scan_status=0
fi

if [[ "$scan_status" -eq 0 ]]; then
  echo "potential secret or credential leak detected" >&2
  exit 1
fi
