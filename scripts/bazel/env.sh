#!/usr/bin/env bash
set -euo pipefail

export PATH="${HOME:-}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

ctxa_workspace_root() {
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

  echo "could not locate ctx authority workspace root" >&2
  return 1
}

ctxa_cache_root() {
  if [[ -n "${TEST_TMPDIR:-}" ]]; then
    local test_cache_root="$TEST_TMPDIR/ctxa-cache"
    mkdir -p "$test_cache_root"
    printf '%s\n' "$test_cache_root"
    return 0
  fi

  local cache_root="${CTXA_CACHE_ROOT:-${TMPDIR:-/tmp}/ctxa-cache}"
  if mkdir -p "$cache_root" 2>/dev/null; then
    printf '%s\n' "$cache_root"
    return 0
  fi

  cache_root="${TMPDIR:-/tmp}/ctxa-cache"
  mkdir -p "$cache_root"
  printf '%s\n' "$cache_root"
}

ctxa_cargo_home() {
  if [[ -n "${CTXA_CARGO_HOME:-}" ]]; then
    printf '%s\n' "$CTXA_CARGO_HOME"
    return 0
  fi

  local package_cache_root="/tmp/ctxa-cargo-home"
  mkdir -p "$package_cache_root"
  (cd "$package_cache_root" && pwd)
}

cache_root="$(ctxa_cache_root)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$cache_root/target}"
export SCCACHE_DIR="${SCCACHE_DIR:-$cache_root/sccache}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

if [[ -z "${CARGO_HOME+x}" ]]; then
  export CARGO_HOME="$(ctxa_cargo_home)"
fi

if [[ -z "${RUSTC_WRAPPER+x}" ]]; then
  use_sccache="${CTXA_USE_SCCACHE:-}"
  if [[ -z "$use_sccache" ]]; then
    case "$(uname -s)" in
      Darwin) use_sccache=0 ;;
      *) use_sccache=1 ;;
    esac
  fi

  if [[ "$use_sccache" == "1" ]] && command -v sccache >/dev/null 2>&1; then
    export RUSTC_WRAPPER="$(command -v sccache)"
  elif [[ "$use_sccache" == "1" && -x /opt/homebrew/bin/sccache ]]; then
    export RUSTC_WRAPPER="/opt/homebrew/bin/sccache"
  else
    export RUSTC_WRAPPER=""
  fi
fi

mkdir -p "$CARGO_HOME" "$CARGO_TARGET_DIR" "$SCCACHE_DIR"

ctxa_codesign_debug_binary_if_needed() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    return 0
  fi
  if [[ "${CTXA_CODESIGN_DEBUG_BINARY:-1}" != "1" ]]; then
    return 0
  fi
  if ! command -v codesign >/dev/null 2>&1; then
    return 0
  fi

  local binary="$CARGO_TARGET_DIR/debug/ctxa"
  if [[ -x "$binary" ]]; then
    local codesign_output
    if ! codesign_output="$(codesign --force --sign - "$binary" 2>&1 >/dev/null)"; then
      printf '%s\n' "$codesign_output" >&2
      return 1
    fi
  fi
}
