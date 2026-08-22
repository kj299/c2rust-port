#!/usr/bin/env bash
# Supply-chain gate — dependencies are part of your memory-safety story. Runs
# cargo-audit (known RUSTSEC advisories) and cargo-deny (advisories + license +
# source/ban policy). A vulnerable or unvetted dependency undoes a careful port.
# (PLAYBOOK cross-cutting controls; SECURITY-CHECKLIST "supply chain".)
#
# Usage:
#   run_supply_chain.sh [CRATE_DIR]     # run the real gate (needs the tools)
#   run_supply_chain.sh --check         # smoke: validate this script + config,
#                                       # report tool availability, never fail
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

have() { command -v "$1" >/dev/null 2>&1; }

# THE verdict: does DIR hold the cargo-deny config this gate needs? Extracted so
# `--check` can run it against a directory that does NOT (LESSONS #25) — the
# happy path alone leaves the predicate unpinned, and the gate-mutation sweep
# proved it: deleting the failure branch kept the self-test green.
have_deny_template() { test -f "$1/deny.template.toml"; }

if [[ "${1:-}" == "--check" ]]; then
  ok=1
  bash -n "$0" && echo "PASS  script syntax ok"
  # Explicit failure branch: under `set -e` a bare `test -f X && echo ok`
  # exits 1 with NO message when X is missing — a silent death in check-kit.
  if have_deny_template "$HERE"; then
    echo "PASS  deny.template.toml present"
  else
    echo "FAIL  deny.template.toml missing from $HERE" >&2
    ok=0
  fi
  # Negative fixture — the pin: an empty directory must NOT satisfy it.
  _empty="$(mktemp -d)"
  if have_deny_template "$_empty"; then
    echo "FAIL  validator finds a deny config in an empty directory" >&2; ok=0
  else
    echo "PASS  validator refuses a directory with no deny config"
  fi
  rmdir "$_empty" 2>/dev/null || true
  [[ "$ok" == "1" ]] || { echo "self-test: FAILED"; exit 1; }
  # tomllib validate the deny config if python is around
  if have python3; then
    python3 - "$HERE/deny.template.toml" <<'PY'
import sys, tomllib
tomllib.load(open(sys.argv[1], "rb"))
print("PASS  deny.template.toml parses")
PY
  fi
  for t in cargo cargo-audit cargo-deny; do
    if have "$t"; then echo "note: $t available"; else echo "note: $t NOT installed (install for the real gate)"; fi
  done
  echo "self-test: OK"
  exit 0
fi

DIR="${1:-.}"
cd "$DIR"
rc=0

if have cargo-audit; then
  echo ">> cargo audit"
  cargo audit || rc=1
else
  echo "!! cargo-audit not installed:  cargo install cargo-audit" >&2
  rc=1
fi

if have cargo-deny; then
  echo ">> cargo deny check"
  # Use the kit's policy unless the crate ships its own deny.toml.
  if [[ -f deny.toml ]]; then
    cargo deny check || rc=1
  else
    cargo deny --config "$HERE/deny.template.toml" check || rc=1
  fi
else
  echo "!! cargo-deny not installed:  cargo install cargo-deny" >&2
  rc=1
fi

exit "$rc"
