#!/usr/bin/env bash
# Sanitizer & Miri gate — catch UB the compiler can't. For a C-to-Rust port the
# FFI/unsafe layer is the residual risk surface; these tools interrogate it:
#   * Miri            — UB in the pure/unsafe Rust (OOB, use-after-free, invalid
#                       aligns, data races in `unsafe`). Runs the test suite.
#                       In Rust this IS the UB detector: rustc has no UBSan.
#   * ASan/LSan/TSan  — the same classes at the real FFI boundary (needs nightly
#                       -Zsanitizer). TSan for threaded code (the winlsof hang
#                       class — worker threads over shared handles).
# (PLAYBOOK Phase 4 gate 4; SECURITY-CHECKLIST "no UB at the FFI boundary".)
#
# LESSONS #22: this harness shipped an `ubsan` mode wired to
# `-Zsanitizer=undefined` — a value rustc REJECTS, so the mode could never pass,
# and `all` (which included it) was permanently red no matter how clean the code.
# A gate that can never go green is as useless as one that can never go red: it
# gets skipped, and a skipped control is a broken control. It survived a 26-finding
# review, the gate-mutation sweep, and a whole port because `--check` validated
# only bash SYNTAX — the same root cause as the original never-runnable sanitizer
# job (LESSONS #6): a self-test that proves nothing about whether the tool works.
# `--check` now verifies every mode maps to a sanitizer rustc actually accepts.
#
# Usage:
#   run_sanitizers.sh [miri|asan|ubsan|lsan|tsan|all] [CRATE_DIR]
#   run_sanitizers.sh --check      # self-test: modes are runnable + tool avail
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }

# The sanitizers rustc's -Zsanitizer accepts. `undefined` is deliberately NOT
# here: Rust has no UBSan backend — miri is the UB detector (see MODE_SAN).
VALID_SANITIZERS="address cfi dataflow hwaddress kcfi kernel-address \
kernel-hwaddress leak memory memtag safestack shadow-call-stack thread realtime"

# THE verdict this harness turns on: is `$1` a sanitizer rustc will accept?
# Neutralize it and the self-test's negative fixture goes red (gate-mutation).
is_valid_san() {
  case " $VALID_SANITIZERS " in
    *" $1 "*) return 0;;
    *) return 1;;
  esac
}

# mode -> what it runs. `miri` is a mode, not a -Zsanitizer value; every OTHER
# entry must name a sanitizer in VALID_SANITIZERS, which --check enforces.
mode_san() {
  case "$1" in
    miri)  echo "miri";;
    ubsan) echo "miri";;   # Rust has no UBSan; miri is the UB detector
    asan)  echo "address";;
    lsan)  echo "leak";;
    tsan)  echo "thread";;
    *)     echo "";;
  esac
}
ALL_MODES="miri ubsan asan lsan tsan"

if [[ "${1:-}" == "--check" ]]; then
  ok=1
  bash -n "$0" && echo "PASS  script syntax ok"
  # THE check that was missing: every mode must be runnable at all. A mode whose
  # sanitizer rustc would reject is a permanently-red gate (LESSONS #22).
  bad=""
  for m in $ALL_MODES; do
    san="$(mode_san "$m")"
    [[ -z "$san" ]] && { bad="$bad $m(unmapped)"; continue; }
    [[ "$san" == "miri" ]] && continue          # miri is not a -Zsanitizer value
    is_valid_san "$san" || bad="$bad $m(-Zsanitizer=$san)"
  done
  if [[ -n "$bad" ]]; then
    echo "FAIL  mode(s) name a sanitizer rustc does not accept:$bad"
    ok=0
  else
    echo "PASS  every mode maps to a runnable checker ($ALL_MODES)"
  fi
  # Negative fixture — the pin (LESSONS #22). Checking that today's modes happen
  # to be valid proves nothing about the VALIDATOR; `undefined` is the exact
  # value this harness shipped for years, so it is the fixture. Without this, a
  # neutered validator still prints PASS above and the gate is theater again.
  if is_valid_san undefined; then
    echo "FAIL  validator accepts '-Zsanitizer=undefined' — the value rustc"
    echo "      rejects and this harness once shipped (LESSONS #22)"
    ok=0
  elif ! is_valid_san address; then
    echo "FAIL  validator rejects '-Zsanitizer=address', which rustc accepts"
    ok=0
  else
    echo "PASS  validator rejects a bogus sanitizer and accepts a real one"
  fi
  # Cross-check the static list against the live toolchain when one is present,
  # so this gate can't rot silently against a future rustc.
  if have rustc && rustc +nightly --version >/dev/null 2>&1; then
    live="$(rustc +nightly - --crate-name probe --print=file-names \
              -Zsanitizer=__bogus__ </dev/null 2>&1 || true)"
    for san in address thread leak; do
      case "$live" in
        *"$san"*) ;;
        *) echo "FAIL  rustc no longer lists '$san' among -Zsanitizer values"; ok=0;;
      esac
    done
    [[ "$ok" == "1" ]] && echo "PASS  live rustc agrees the sanitizer names exist"
  else
    echo "note: no nightly rustc here — static sanitizer list not cross-checked"
  fi
  if have rustup; then
    # against the NIGHTLY toolchain: `rustup component list` with no --toolchain
    # reports the default (stable) one, where miri never appears — so this note
    # said "install miri" even with miri installed and working.
    if cargo +nightly miri --version >/dev/null 2>&1; then
      echo "note: miri is installed and runnable on nightly"
    else
      echo "note: install miri:  rustup component add --toolchain nightly miri"
    fi
  else
    echo "note: rustup not installed (needed for miri/nightly sanitizers)"
  fi
  if [[ "$ok" == "1" ]]; then echo "self-test: OK"; exit 0
  else echo "self-test: FAILED"; exit 1; fi
fi

MODE="${1:-all}"; DIR="${2:-.}"
shift || true; shift || true
# Anything after `--` is passed through to cargo, so a port can scope the run to
# the crates that matter (`-- -p foo -p bar`). Without this a port has to
# hand-roll its own cargo invocation — which is exactly what the cJSON port did,
# leaving this harness unexercised against real code for its whole life
# (LESSONS #22): a harness nothing calls is a harness nothing tests.
[[ "${1:-}" == "--" ]] && shift
CARGO_ARGS=("$@")
cd "$DIR"
TRIPLE="$(rustc -vV 2>/dev/null | awk '/host:/{print $2}')"
rc=0

run_miri() {
  if have cargo && rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo ">> cargo +nightly miri test"
    cargo +nightly miri test "${CARGO_ARGS[@]}" || rc=1
  else
    echo "!! miri needs nightly:  rustup toolchain install nightly && rustup +nightly component add miri" >&2
    rc=1
  fi
}

run_san() {
  local san="$1"
  # Refuse an unknown sanitizer LOUDLY instead of handing rustc a value it
  # rejects and reporting the resulting build failure as a finding (LESSONS #22).
  if ! is_valid_san "$san"; then
    echo "!! internal: '$san' is not a -Zsanitizer value rustc accepts" >&2
    rc=1; return
  fi
  if [[ -z "$TRIPLE" ]]; then
    echo "!! rustc not found — cannot determine the target triple for -Zsanitizer=$san" >&2
    rc=1
    return
  fi
  if rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo ">> cargo +nightly test with -Zsanitizer=$san"
    RUSTFLAGS="-Zsanitizer=$san" RUSTDOCFLAGS="-Zsanitizer=$san" \
      cargo +nightly test --target "$TRIPLE" "${CARGO_ARGS[@]}" || rc=1
  else
    echo "!! $san sanitizer needs the nightly toolchain" >&2
    rc=1
  fi
}

case "$MODE" in
  miri)  run_miri;;
  ubsan) echo "note: Rust has no UBSan (-Zsanitizer has no 'undefined' value);"
         echo "      miri is the UB detector — running it instead."
         run_miri;;
  asan)  run_san address;;
  lsan)  run_san leak;;
  tsan)  run_san thread;;
  all)   run_miri; run_san address
         # Say the omission out loud: a silent skip reads as coverage.
         echo "note: 'all' = miri (UB) + asan (FFI memory errors). TSan and LSan"
         echo "      are NOT included (slow; TSan only meaningful with threaded"
         echo "      tests) — run '$0 tsan' / '$0 lsan' explicitly for threaded"
         echo "      code (the winlsof hang class) or leak hunts.";;
  *) echo "usage: $0 [miri|asan|ubsan|lsan|tsan|all] [CRATE_DIR] | --check" >&2; exit 2;;
esac
exit "$rc"
