#!/usr/bin/env bash
set -euo pipefail

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Volumes/ctx-cache/authority-broker/target}"
export SCCACHE_DIR="${SCCACHE_DIR:-/Volumes/ctx-cache/authority-broker/sccache}"
export RUSTC_WRAPPER="${RUSTC_WRAPPER:-/opt/homebrew/bin/sccache}"
mkdir -p "$CARGO_TARGET_DIR" "$SCCACHE_DIR"
