#!/usr/bin/env bash
# Supply-chain gate — dependencies are part of your memory-safety story. Runs
# cargo-audit (known RUSTSEC advisories) and cargo-deny (advisories + license +
# source/ban policy). A vulnerable or unvetted dependency undoes a careful port.
# (CLAUDE.md's control table, "clean deps"; SECURITY-CHECKLIST "supply chain".)
#
# Usage:
#   run_supply_chain.sh [CRATE_DIR]     # run the real gate (needs the tools)
#   run_supply_chain.sh --check         # smoke: validate this script + config,
#                                       # report tool availability; fails if the
#                                       # script does not parse or the config is gone
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
  # `bash -n "$0" && echo PASS` could not fail this check: under `set -e` a
  # failing command inside an `&&` list does not stop the script (LESSONS #54).
  if bash -n "$0"; then echo "PASS  script syntax ok"
  else echo "FAIL  this script does not parse"; ok=0; fi
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
  # tomllib only proves the file is TOML. cargo-deny is the parser that matters:
  # until 2026-10-24 this template said `wildcard-dependencies`, a key cargo-deny
  # rejects outright, and this self-test passed it for as long as nothing ever
  # ran the real tool (LESSONS #65). So where cargo-deny exists, load the
  # template the way the gate does, against a one-crate fixture — and a copy
  # with a misspelt key must be REFUSED, or the check proves nothing.
  if have cargo && have cargo-deny; then
    _fx="$(mktemp -d)"
    mkdir -p "$_fx/src"
    printf '[package]\nname = "fx"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\npublish = false\n' > "$_fx/Cargo.toml"
    : > "$_fx/src/lib.rs"
    if ( cd "$_fx" && cargo generate-lockfile -q --offline 2>/dev/null || cargo generate-lockfile -q ) \
       && ( cd "$_fx" && cargo deny --config "$HERE/deny.template.toml" check bans licenses sources >/dev/null 2>&1 ); then
      echo "PASS  cargo-deny loads deny.template.toml and a clean crate passes it"
    else
      echo "FAIL  cargo-deny rejects deny.template.toml (or a clean crate fails it)" >&2; ok=0
    fi
    sed 's/^wildcards = /wildcard-dependencies = /' "$HERE/deny.template.toml" > "$_fx/bad.toml"
    if ( cd "$_fx" && cargo deny --config "$_fx/bad.toml" check bans >/dev/null 2>&1 ); then
      echo "FAIL  cargo-deny accepted a template with an unknown key — the check above proves nothing" >&2; ok=0
    else
      echo "PASS  cargo-deny refuses a template with an unknown key"
    fi
    rm -rf "$_fx"
  else
    echo "note: cargo-deny absent — the template was NOT loaded by the tool that reads it"
  fi
  [[ "$ok" == "1" ]] || { echo "self-test: FAILED"; exit 1; }
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
