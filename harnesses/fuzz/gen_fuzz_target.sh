#!/usr/bin/env bash
# Fuzz-target scaffolder — generate a cargo-fuzz target skeleton for a newly
# ported module's public parse/input API. Fuzzing the input surface is where a
# C-to-Rust rewrite proves it removed the memory-safety bugs: any panic/crash on
# untrusted input is a release blocker (PLAYBOOK Phase 4, gate 3).
#
# Usage:
#   gen_fuzz_target.sh <module_name> [--crate CRATE] [--out DIR]
#   gen_fuzz_target.sh --check          # smoke test: generate to a temp dir, verify
#
# Produces DIR/fuzz_targets/<module_name>.rs from the template, and prints the
# one-time setup (cargo install cargo-fuzz; cargo fuzz init) if not already done.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="$HERE/fuzz_target.template.rs"

emit() {
  local module="$1" crate="$2" out="$3"
  mkdir -p "$out/fuzz_targets"
  sed -e "s/__MODULE__/$module/g" -e "s/__CRATE__/$crate/g" \
      "$TEMPLATE" > "$out/fuzz_targets/${module}.rs"
  echo "wrote $out/fuzz_targets/${module}.rs"
}

# THE verdict: is FILE a properly generated, fully substituted fuzz target?
# Extracted so `--check` can run it against a KNOWN-BAD file as well as a good
# one (LESSONS #25). Checking only the happy path proves the scaffolder works,
# never that this predicate would refuse anything — the gate-mutation sweep
# neutralized it and the self-test stayed green, which is the same
# proves-detection-never-refusal root cause as LESSONS #6.
valid_target() {
  local f="$1"
  test -f "$f" || return 1
  grep -q "fuzz_target!" "$f" || return 1
  grep -q "mycrate" "$f" || return 1
  return 0
}

if [[ "${1:-}" == "--check" ]]; then
  ok=1
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  emit "parser" "mycrate" "$tmp" >/dev/null
  if valid_target "$tmp/fuzz_targets/parser.rs"; then
    echo "PASS  fuzz scaffolder generates a valid target"
  else
    echo "FAIL  scaffolder did not produce a valid target"; ok=0
  fi
  # Negative fixtures — the pin. Each is a way generation can go wrong:
  # a missing file, an unexpanded template, an unsubstituted crate name.
  printf 'fn main() {}\n' > "$tmp/unexpanded.rs"          # no fuzz_target!
  printf 'fuzz_target!(|d: &[u8]| { __CRATE__::go(d); });\n' > "$tmp/nosubst.rs"
  if valid_target "$tmp/missing.rs" || valid_target "$tmp/unexpanded.rs" \
     || valid_target "$tmp/nosubst.rs"; then
    echo "FAIL  validator accepts a missing / unexpanded / unsubstituted target"
    ok=0
  else
    echo "PASS  validator refuses missing, unexpanded and unsubstituted targets"
  fi
  if [[ "$ok" == "1" ]]; then echo "self-test: OK"; exit 0
  else echo "self-test: FAILED"; exit 1; fi
fi

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <module_name> [--crate CRATE] [--out DIR]  |  $0 --check" >&2
  exit 2
fi

MODULE="$1"; shift
CRATE="mycrate"; OUT="fuzz"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --crate) CRATE="$2"; shift 2;;
    --out)   OUT="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

emit "$MODULE" "$CRATE" "$OUT"
cat <<EOF

Next steps (one-time, if not already set up):
  cargo install cargo-fuzz
  cargo fuzz init                       # if this crate has no fuzz/ yet
  cargo fuzz run $MODULE -- -max_total_time=60     # smoke
  cargo fuzz run $MODULE                            # deep (nightly / CI schedule)
Seed the corpus with real inputs and any crash reproducers you find.
EOF
