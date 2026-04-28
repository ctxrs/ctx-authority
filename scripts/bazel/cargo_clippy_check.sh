#!/usr/bin/env bash
set -euo pipefail
cd "${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
source scripts/bazel/env.sh
cargo clippy --all-targets --all-features -- -D warnings
