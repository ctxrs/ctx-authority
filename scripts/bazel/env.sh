#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME:-}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

authority_broker_workspace_root() {
  if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" && -f "$BUILD_WORKSPACE_DIRECTORY/Cargo.toml" ]]; then
    printf '%s\n' "$BUILD_WORKSPACE_DIRECTORY"
    return 0
  fi

  if [[ -n "${TEST_SRCDIR:-}" && -n "${TEST_WORKSPACE:-}" && -f "$TEST_SRCDIR/$TEST_WORKSPACE/Cargo.toml" ]]; then
    printf '%s\n' "$TEST_SRCDIR/$TEST_WORKSPACE"
    return 0
  fi

  local env_dir
  env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$env_dir/../../Cargo.toml" ]]; then
    (cd "$env_dir/../.." && pwd)
    return 0
  fi

  if git_root="$(git rev-parse --show-toplevel 2>/dev/null)" && [[ -f "$git_root/Cargo.toml" ]]; then
    printf '%s\n' "$git_root"
    return 0
  fi

  if [[ -f Cargo.toml ]]; then
    pwd
    return 0
  fi

  echo "could not locate authority-broker workspace root" >&2
  return 1
}

authority_broker_cache_root() {
  if [[ -n "${TEST_TMPDIR:-}" ]]; then
    local test_cache_root="$TEST_TMPDIR/authority-broker-cache"
    mkdir -p "$test_cache_root"
    printf '%s\n' "$test_cache_root"
    return 0
  fi

  local cache_root="${AUTHORITY_BROKER_CACHE_ROOT:-/Volumes/ctx-cache/authority-broker}"
  if mkdir -p "$cache_root" 2>/dev/null; then
    printf '%s\n' "$cache_root"
    return 0
  fi

  cache_root="${TMPDIR:-/tmp}/authority-broker-cache"
  mkdir -p "$cache_root"
  printf '%s\n' "$cache_root"
}

cache_root="$(authority_broker_cache_root)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$cache_root/target}"
export SCCACHE_DIR="${SCCACHE_DIR:-$cache_root/sccache}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

if [[ -z "${RUSTC_WRAPPER+x}" ]]; then
  if command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER="$(command -v sccache)"
  elif [[ -x /opt/homebrew/bin/sccache ]]; then
    export RUSTC_WRAPPER="/opt/homebrew/bin/sccache"
  else
    export RUSTC_WRAPPER=""
  fi
fi

mkdir -p "$CARGO_TARGET_DIR" "$SCCACHE_DIR"
