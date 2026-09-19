#!/usr/bin/env bash
# TEMPLATE port gate — copy this next to your port and fill in the PORT-SPECIFIC
# blocks. It ships with **every control in the kit's CLAUDE.md table already
# wired**, because that is the failure this template exists to prevent.
#
# Why this file exists (LESSONS #31): the kit had no gate template, so each port
# assembled `check.sh` by hand. The cJSON port's ended up never invoking three of
# the six script-backed controls — `supply-chain`, `c-flaw-scan` and
# `threat-model`, two of them "hard fail" — and nothing noticed, because the
# gate-mutation sweep measures a harness's self-test, not its use. Starting from
# a template that already calls everything makes the safe arrangement the default
# one, and step 0 below re-checks it on every run.
#
# Deliberately FAIL-CLOSED, not skip-friendly: the port-specific blocks abort
# until you fill them in. A template that quietly passes with nothing wired would
# be the same bug in a new costume (LESSONS #6/#18).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="${KIT:-$HERE/porting-kit}"       # where the kit is vendored
PY="${PYTHON:-python3}"

[ -d "$KIT/harnesses" ] || { echo "set KIT=<path to the vendored porting-kit>"; exit 2; }

echo "===== 0. declared controls — every one in CLAUDE.md's table must RUN here ====="
# The gate above the gates. Fails if a control below is ever dropped.
"$PY" "$KIT/harnesses/control-coverage/check_controls.py" \
    --controls "$KIT/CLAUDE.md" --gate "$HERE/check.sh"

echo "===== 0b. Phase-0 controls — re-run against the C actually ported ====="
# Re-run EVERY gate, not once at Phase 0: the C in scope grows as modules land,
# and a source added later would otherwise arrive un-triaged (LESSONS #31).
"$PY" "$KIT/harnesses/c-flaw-scan/scan_c_flaws.py" "$HERE/c" | tail -4
"$PY" "$KIT/harnesses/threat-model/check_threat_model.py" "$HERE/THREAT-MODEL.md"
# Every exported symbol must be accounted for: `ported`, or `unported` /
# `out-of-scope` WITH a written reason, with the unported count held to the
# ceiling the manifest declares (LESSONS #34/#35).
# PORT-SPECIFIC: pass --header ONCE PER PUBLIC HEADER — all of them, in one
# invocation against one manifest. Naming only the header you just worked on is
# how the cJSON port stayed green with 35 base-library entry points ungated:
# scoping the checker narrowly moves the hole into the checker. Set
# --export-macro to your library's export marker if it is not CJSON_PUBLIC.
"$PY" "$KIT/harnesses/api-coverage/check_api.py" \
    --header "$HERE/c/lib.h" --manifest "$HERE/API-COVERAGE.md"

echo "===== 1. rust workspace (fmt / clippy / build / test) ====="
( cd "$HERE/rust"
  cargo fmt --all -- --check
  cargo clippy --all-targets --release -- -D warnings
  cargo build --release --quiet
  cargo test --all --quiet )

echo "===== 2. differential — Rust vs C over the ported modules ====="
# PORT-SPECIFIC: build your oracle and point this at your matrix.
mkdir -p "$HERE/reports"
if [ ! -x "$HERE/oracle/oracle" ] || [ ! -f "$HERE/oracle/matrix.json" ]; then
  echo "TODO: build oracle/oracle and write oracle/matrix.json, then delete this guard." >&2
  exit 2
fi
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/oracle" --rust "$HERE/rust/target/release/driver" \
    --matrix "$HERE/oracle/matrix.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/MODULE.json"

echo "===== 3. diff-fuzz ====="
# The iteration count here is a REGRESSION FLOOR, not proof of sufficiency
# (LESSONS #33): before calling a module DONE, run a high-budget sweep separately
# — >=10x this budget, >=2 seeds, every mode — and argue the budget from the
# module's real input space rather than inheriting this number.
mkdir -p "$HERE/reports/fuzz"
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/oracle" --rust "$HERE/rust/target/release/driver" \
    --matrix "$HERE/oracle/matrix.json" --ledger "$HERE/DIVERGENCES.md" \
    --iterations 2000 --timeout 5 --json > "$HERE/reports/fuzz/MODULE.json"

echo "===== 3c. oracle-sanitize — the C DRIVER is code this port wrote ====="
# LESSONS #40. `oracle/driver.c` is not vendored C, it is yours: it sizes
# buffers and transfers ownership by hand, and a leak or an overread there
# changes no stdout, so the differential and the fuzzer stay green over it.
# Build a sanitized twin of the same sources and drive every matrix case
# through it. Toolchain-optional, but the SKIP must be loud.
# Three outcomes, not two. "You have not written the build script" and "your
# compiler cannot do ASan" are different facts, and reporting the second when the
# first is true tells a port its environment is thin when actually its control is
# missing — the same conflation LESSONS #40's own self-test had.
if [ ! -x "$HERE/oracle/build_asan.sh" ]; then
  echo "TODO  oracle-sanitize: no oracle/build_asan.sh yet. Write one (same"
  echo "      sources as build.sh, plus -fsanitize=address,undefined) — until"
  echo "      then the C driver you wrote is checked by nothing."
elif bash "$HERE/oracle/build_asan.sh" > /dev/null 2>&1; then
  # one --matrix flag per file: the flag takes a single path, so a bare glob
  # would hand argparse positionals it rejects.
  SAN_MATRICES=()
  for m in "$HERE"/oracle/matrix*.json; do SAN_MATRICES+=(--matrix "$m"); done
  "$PY" "$KIT/harnesses/oracle-sanitize/sanitize_oracle.py" \
      --oracle "$HERE/oracle/oracle_asan" "${SAN_MATRICES[@]}"
else
  echo "SKIP  oracle-sanitize: build_asan.sh exists but did not build (no"
  echo "      ASan-capable compiler?). The C driver was NOT checked this run."
fi

echo "===== 4. sanitizers (toolchain-optional, but SKIP must be loud) ====="
mkdir -p "$HERE/reports/sanitize"
if cargo +nightly miri --version >/dev/null 2>&1; then
  bash "$KIT/harnesses/sanitizers/run_sanitizers.sh" all "$HERE/rust" \
      --json "$HERE/reports/sanitize/MODULE.json"
else
  echo "SKIP  sanitizers: no nightly+miri — no report written, so the sanitized"
  echo "      rung cannot advance (an unrun gate proves nothing, LESSONS #18)."
fi

echo "===== 5. unsafe-audit ====="
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates"

echo "===== 5b. supply-chain — the dependency surface ====="
if command -v cargo-audit >/dev/null 2>&1 && command -v cargo-deny >/dev/null 2>&1; then
  bash "$KIT/harnesses/supply-chain/run_supply_chain.sh" "$HERE/rust"
else
  echo "SKIP  supply-chain: cargo-audit/cargo-deny absent — the dependency audit"
  echo "      did NOT run (cargo install cargo-audit cargo-deny). Reported every"
  echo "      run so an unaudited dependency tree cannot look green."
fi

echo "===== 6. progress — rungs must be EARNED from THIS run's reports ====="
# Replay into a scratch table seeded at `ported`, so a rung that quietly stopped
# being provable cannot coast on the committed table (LESSONS #24).
( cd "$KIT" && "$PY" harnesses/progress/progress.py --file "$HERE/progress.json" ingest \
    --diff-json "$HERE"/reports/*.json \
    --fuzz-json "$HERE"/reports/fuzz/*.json \
    --sanitize-json "$HERE"/reports/sanitize/*.json )

echo ""
echo "===== PORT GATE COMPLETE ====="
