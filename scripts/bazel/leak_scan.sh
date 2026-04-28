#!/usr/bin/env bash
set -euo pipefail
cd "${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"

if rg -n 'pinterest|lawsuit|schwab|nfcu|attorney|api_key|sk-[A-Za-z0-9]|BEGIN RSA|BEGIN OPENSSH|password\s*=|token\s*=' . --glob '!target/**' --glob '!.git/**' --glob '!.local/**'; then
  echo "potential public leak detected" >&2
  exit 1
fi
