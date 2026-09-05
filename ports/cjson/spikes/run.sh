#!/usr/bin/env bash
# Reproduce the mutation-API hazards documented in ../MUTATION-API-SPIKE.md
# against the vendored cJSON, under ASan + UBSan.
#
# These are SPIKE programs, not gates: `check.sh` does not run them, and two of
# the three are EXPECTED to abort. They are committed because the spike document
# makes claims about a dependency's behavior, and a claim whose evidence lives
# only in the session that made it is a claim nobody can re-check later
# (LESSONS #32). Run this to re-derive every quoted result from scratch.
#
# Usage: bash spikes/run.sh
set -uo pipefail                 # NOT -e: the first spike is meant to crash
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../c"
CC="${CC:-cc}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

run() {
  local name="$1" expect="$2"
  echo
  echo "===== $name (expect: $expect) ====="
  "$CC" -O1 -g -fsanitize=address,undefined -I "$SRC" \
      "$HERE/$name.c" "$SRC/cJSON.c" -lm -o "$OUT/$name" || return 1
  "$OUT/$name" 2>&1 | head -20
  echo "--- exit status: ${PIPESTATUS[0]} ---"
}

run detach_null_write            "ASan SEGV, WRITE, cJSON.c:2231"
run detach_cross_document        "B modified though only A was named"
run detach_corruption_cashes_in  "append to A lands in B"
