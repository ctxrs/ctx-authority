#!/usr/bin/env bash
set -euo pipefail
cd "${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"

scripts/bazel/cargo_fmt_check.sh
scripts/bazel/cargo_clippy_check.sh
scripts/bazel/cargo_test.sh
scripts/bazel/cli_smoke_test.sh
scripts/bazel/leak_scan.sh
