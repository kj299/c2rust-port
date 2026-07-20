#!/usr/bin/env bash
# Skeleton gate — the shipped skeleton must PASS the gates it configures. It sets
# strict workspace lints ([workspace.lints]: arithmetic_side_effects,
# cast_possible_truncation, the unsafe docs) and the kit's CI runs `cargo fmt
# --check` + `cargo clippy --all-targets -- -D warnings` + build + test. If the
# skeleton itself fails those, every port that copies it starts RED (LESSONS #9:
# a template must pass the gates it ships). Nothing caught this before because
# `make check-kit` was toolchain-free and never built the skeleton.
#
# This gate is toolchain-OPTIONAL so check-kit still runs with only python3+bash:
# with no cargo it prints SKIP and exits 0; with cargo it runs the real checks.
# The skeleton has no external dependencies, so the build/test is offline.
#
# Usage:
#   check_skeleton.sh [SKELETON_DIR]   # real gate when cargo is present, else SKIP
#   check_skeleton.sh --check          # smoke: validate this script; report cargo
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }
DEFAULT_SKEL="$HERE/../../skeleton"

if [[ "${1:-}" == "--check" ]]; then
  bash -n "$0" && echo "PASS  script syntax ok"
  test -d "$DEFAULT_SKEL" && echo "PASS  skeleton dir present" || { echo "FAIL  skeleton dir missing: $DEFAULT_SKEL" >&2; exit 1; }
  if have cargo; then echo "note: cargo present — the skeleton gate runs the real fmt/clippy/build/test"
  else echo "note: cargo absent — the skeleton gate will SKIP (install a Rust toolchain to run it)"; fi
  echo "self-test: OK"
  exit 0
fi

SKEL="${1:-$DEFAULT_SKEL}"
if ! have cargo; then
  echo "SKIP  skeleton gate: no cargo on PATH (install a Rust toolchain to run it)"
  exit 0
fi
cd "$SKEL"
echo ">> cargo fmt --all -- --check";                cargo fmt --all -- --check
echo ">> cargo clippy --all-targets -- -D warnings"; cargo clippy --all-targets -- -D warnings
echo ">> cargo build --release";                     cargo build --release
echo ">> cargo test --all";                          cargo test --all
echo "PASS  skeleton passes the gates it ships"
