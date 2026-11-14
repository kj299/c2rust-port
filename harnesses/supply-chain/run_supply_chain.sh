#!/usr/bin/env bash
# Supply-chain gate — dependencies are part of your memory-safety story. Runs
# cargo-audit (known RUSTSEC advisories) and cargo-deny (advisories + license +
# source/ban policy). A vulnerable or unvetted dependency undoes a careful port.
# (CLAUDE.md's control table, "clean deps"; SECURITY-CHECKLIST "supply chain".)
#
# Usage:
#   run_supply_chain.sh [DIR]           # run the real gate (needs the tools) on
#                                       # EVERY Cargo.lock under DIR, each held to
#                                       # the nearest deny.toml at or above it
#   run_supply_chain.sh --check         # smoke: validate this script + config,
#                                       # report tool availability; fails if the
#                                       # script does not parse or the config is gone
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT_ROOT="$(cd "$HERE/../.." && pwd -P)"

have() { command -v "$1" >/dev/null 2>&1; }

# THE verdict: does DIR hold the cargo-deny config this gate needs? Extracted so
# `--check` can run it against a directory that does NOT (LESSONS #25) — the
# happy path alone leaves the predicate unpinned, and the gate-mutation sweep
# proved it: deleting the failure branch kept the self-test green.
have_deny_template() { test -f "$1/deny.template.toml"; }

# Which lockfiles the gate audits: one per line, relative to DIR. Every one git
# tracks under DIR (outside a work tree, every one not under a `target/`), less
# the lockfiles of this kit itself where it is vendored inside DIR: those are the
# kit's examples, not the port's dependencies. This gate audited DIR's own
# lockfile and nothing else, and a workspace nested in it has one of its own:
# cargo-fuzz makes `fuzz/` a workspace, so the CI template, which runs this on
# `.`, left every port's fuzz lockfile unaudited. The lsof line found its own
# that way: libfuzzer-sys, and the `cc` build script that compiles libFuzzer,
# read by no audit (LESSONS #66).
port_lockfiles() { # DIR KIT
  local dir kit lock
  dir="$(cd "$1" && pwd -P)"; kit="$(cd "$2" && pwd -P)"
  {
    if git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git -C "$dir" ls-files -- '*Cargo.lock'
    else
      ( cd "$dir" && find . -name Cargo.lock -not -path '*/target/*' | sed 's|^\./||' )
    fi
  } | LC_ALL=C sort | while IFS= read -r lock; do
    case "$dir/" in "$kit/"*) echo "$lock"; continue ;; esac  # auditing the kit itself
    case "$dir/$lock" in "$kit/"*) continue ;; esac           # the vendored kit's own
    echo "$lock"
  done
}

# The cargo-deny policy for the workspace WS (relative to ROOT): the nearest
# `deny.toml` from WS up to ROOT, else this kit's template. The gate looked in
# the audited directory alone, so a nested workspace was held to the template
# rather than to the policy the port ships beside it (LESSONS #66).
deny_config() { # ROOT WS
  local root d
  root="$(cd "$1" && pwd -P)"; d="$(cd "$1/$2" && pwd -P)"
  while :; do
    if [[ -f "$d/deny.toml" ]]; then echo "$d/deny.toml"; return; fi
    [[ "$d" == "$root" || "$d" == "/" ]] && break
    d="$(dirname "$d")"
  done
  echo "$HERE/deny.template.toml"
}

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
  # Every lockfile, and the policy each is held to (LESSONS #66). A port with a
  # fuzz workspace and a vendored kit, listed outside git and then in it: both
  # of the port's lockfiles, never one under `target/`, never the kit's own.
  _t="$(mktemp -d)"; _t="$(cd "$_t" && pwd -P)"
  export GIT_CEILING_DIRECTORIES="$_t"   # "outside git" must not find a repo above
  mkdir -p "$_t/port/fuzz" "$_t/port/target/release" "$_t/port/porting-kit/skeleton"
  : > "$_t/port/Cargo.lock"; : > "$_t/port/fuzz/Cargo.lock"
  : > "$_t/port/target/release/Cargo.lock"; : > "$_t/port/porting-kit/skeleton/Cargo.lock"
  _got="$(port_lockfiles "$_t/port" "$_t/port/porting-kit" | tr '\n' ' ')"
  if [[ "$_got" == "Cargo.lock fuzz/Cargo.lock " ]]; then
    echo "PASS  outside git: every lockfile, none under target/ and none of the vendored kit's"
  else
    echo "FAIL  outside git the gate would audit: ${_got:-nothing}" >&2; ok=0
  fi
  if have git; then
    git -C "$_t/port" -c init.defaultBranch=main -c maintenance.auto=false -c gc.auto=0 init -q
    git -C "$_t/port" -c maintenance.auto=false -c gc.auto=0 \
        add Cargo.lock fuzz/Cargo.lock porting-kit/skeleton/Cargo.lock
    _got="$(port_lockfiles "$_t/port" "$_t/port/porting-kit" | tr '\n' ' ')"
    if [[ "$_got" == "Cargo.lock fuzz/Cargo.lock " ]]; then
      echo "PASS  in a work tree: every tracked lockfile, none of the vendored kit's"
    else
      echo "FAIL  in a work tree the gate would audit: ${_got:-nothing}" >&2; ok=0
    fi
  else
    echo "note: git absent — the work-tree listing was NOT exercised"
  fi
  if [[ "$(port_lockfiles "$_t/port/porting-kit" "$_t/port/porting-kit")" == "skeleton/Cargo.lock" ]]; then
    echo "PASS  run on the kit itself, the kit's lockfiles are audited"
  else
    echo "FAIL  run on the kit itself, its own lockfiles were dropped" >&2; ok=0
  fi
  : > "$_t/port/deny.toml"
  if [[ "$(deny_config "$_t/port" fuzz)" == "$_t/port/deny.toml" ]]; then
    echo "PASS  a nested workspace is held to the port's deny.toml above it"
  else
    echo "FAIL  a nested workspace is held to $(deny_config "$_t/port" fuzz)" >&2; ok=0
  fi
  if [[ "$(deny_config "$_t/port/fuzz" .)" == "$HERE/deny.template.toml" ]]; then
    echo "PASS  no deny.toml at or below the audited directory: the template"
  else
    echo "FAIL  the policy search left the audited directory" >&2; ok=0
  fi
  rm -rf "$_t"; unset GIT_CEILING_DIRECTORIES
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
[[ -d "$DIR" ]] || { echo "!! $DIR: no such directory" >&2; exit 2; }
mapfile -t LOCKS < <(port_lockfiles "$DIR" "$KIT_ROOT")
# Nothing to audit is not a clean audit: a gate that finds no lockfile has
# checked nothing, and says so by failing.
if [[ "${#LOCKS[@]}" -eq 0 ]]; then
  echo "!! no Cargo.lock under $DIR: nothing was audited" >&2
  exit 1
fi
rc=0
for lock in "${LOCKS[@]}"; do
  ws="$(dirname "$lock")"
  echo "== $DIR/$lock"
  if have cargo-audit; then
    echo ">> cargo audit"
    cargo audit --file "$DIR/$lock" || rc=1
  else
    echo "!! cargo-audit not installed: the RUSTSEC check did not run" >&2
    rc=1
  fi
  if have cargo-deny; then
    cfg="$(deny_config "$DIR" "$ws")"
    echo ">> cargo deny check  (policy: $cfg)"
    cargo deny --manifest-path "$DIR/$ws/Cargo.toml" --config "$cfg" check || rc=1
  else
    echo "!! cargo-deny not installed: the licence/source/ban policy did not run" >&2
    rc=1
  fi
done
echo "audited ${#LOCKS[@]} lockfile(s) under $DIR"
exit "$rc"
