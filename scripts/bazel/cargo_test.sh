#!/usr/bin/env bash
set -euo pipefail
cd "${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
source scripts/bazel/env.sh
cargo test --all-targets --all-features
