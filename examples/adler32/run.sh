#!/usr/bin/env bash
# v1.0 EXIT TEST — drive a real tiny C→Rust library port through the whole kit.
#
# The C (`c/adler32.c`) is the "obvious" Adler-32: it accumulates s1/s2 in
# uint32_t and takes the modulo only at the end, so s2 OVERFLOWS on long inputs.
# The Rust (`rust/`) blocks every NMAX bytes like zlib over a bounds-checked
# slice — safer AND more correct. That difference is a *finding*, ledgered as an
# intentional fix-of-C-defect. This script drives every gate over the pair.
#
# Needs cc + cargo (unlike `make check-kit`, which is python3+bash only), so it
# is NOT part of check-kit — it is the runnable demo the toolchain-free suite
# can't be. Run:  examples/adler32/run.sh
# -e: this script IS a gate — any harness that exits nonzero must abort the run
# before the success banner (LESSONS #6: a gate that finds nothing to check, or
# swallows a failure, must not pass).
set -euo pipefail
cd "$(dirname "$0")"
K=../../harnesses
PY=python3
mkdir -p reports

echo "===== build (C .so/cli/driver + Rust cdylib/cli/driver) ====="
cc -O2 -shared -fPIC -o libadler_c.so c/adler32.c
cc -O2 -o adler_cli_c c/adler_cli.c c/adler32.c
cc -O2 -o adler_drv_c c/adler_drv.c c/adler32.c
( cd rust && cargo build --release --quiet )
CDYLIB=rust/target/release/libradler.so
CLI=rust/target/release/radler_cli
DRV=rust/target/release/adler_drv

echo "===== cargo test (port correctness on known vectors) ====="
# Capture-then-filter so a test FAILURE aborts (the old `| grep ... || true`
# swallowed it — the exit test's own unit-test gate failed open).
test_out=$(cargo test --manifest-path rust/Cargo.toml --quiet 2>&1) \
  || { echo "$test_out"; echo "FAIL: cargo test"; exit 1; }
echo "$test_out" | grep -E "test result" || true

echo "===== Phase 0 — scan_c_flaws (arithmetic bug is NOT a grep-able sink) ====="
$PY $K/c-flaw-scan/scan_c_flaws.py c/adler32.c

echo "===== unsafe-audit (Rust FFI export) ====="
$PY $K/unsafe-audit/audit_unsafe.py rust/src

# --- generate the overflow input + all vector/matrix suites ---
$PY - <<'PYGEN'
import json
big = "a" * 10000
json.dump([{"name":"empty","func":"adler32","args":[""]},
           {"name":"wikipedia","func":"adler32","args":["Wikipedia"]},
           {"name":"fox","func":"adler32","args":["The quick brown fox"]},
           {"name":"overflow","func":"adler32","args":[big]}],
          open("cando_vectors.gen.json","w"))
mk = lambda n,s,l: {"name":n,"function":"adler32","returns":"uint",
    "args":[{"type":"cstr","value":s,"id":"d"},{"type":"size_t","value":l}]}
json.dump([mk("empty","",0), mk("wikipedia","Wikipedia",9),
           mk("fox","The quick brown fox",19), mk("overflow-10k-a",big,10000)],
          open("lib_vectors.gen.json","w"), indent=2)
json.dump([{"name":"wiki","args":[],"stdin":"Wikipedia"},
           {"name":"abc","args":[],"stdin":"abc"}], open("matrix.gen.json","w"))
json.dump([{"name":"fox","args":[],"stdin":"The quick brown fox"}], open("hold.gen.json","w"))
json.dump([{"name":"perf-5MB","args":[],"stdin":"a"*5_000_000}], open("perf.gen.json","w"))
print("generated vector/matrix suites")
PYGEN

# The two library differentials find the SAME overflow. PIN each acceptance to
# its fingerprint (LESSONS #8): a name-only entry would mute the vector forever,
# hiding any NEW regression in it; a pinned entry re-fails if the divergence ever
# changes shape. (Fingerprints are deterministic: adler32 is pure arithmetic. If
# a harness's diff format changes, these pins re-fail loudly — that is the pin
# doing its job; re-derive with `--ledger /dev/null --json` and update.)
cat > DIVERGENCES.md <<'EOF'
# Intentional divergences — adler32 port (fix-of-C-defect, prime directive)
- [x] overflow [sha256:77af9ad455c0]: the C reference overflows its uint32 s2
  accumulator on long inputs; the Rust port blocks per NMAX=5552 and is
  correct. (cando driver.)
- [x] overflow-10k-a [sha256:f1dff6ae73c9]: the same defect, seen through
  lib_diff (ctypes).
EOF

echo "===== cando — main's driver-based library differential (+ baseline validation) ====="
$PY $K/cando/cando_diff.py --oracle-driver ./adler_drv_c --rust-driver "$DRV" \
    --vectors cando_vectors.gen.json --ledger DIVERGENCES.md

echo "===== lib_diff — complementary ctypes library differential ====="
$PY $K/library-differential/lib_diff.py --c-lib ./libadler_c.so --rust-lib "$CDYLIB" \
    --vectors lib_vectors.gen.json --ledger DIVERGENCES.md

echo "===== golden — capture C with --validate + --holdout; replay Rust ====="
$PY $K/golden/golden.py capture --oracle ./adler_cli_c --matrix matrix.gen.json \
    --corpus corpus --holdout hold.gen.json --validate
echo "-- iteration replay (held-out vector excluded) --"
$PY $K/golden/golden.py replay --rust "$CLI" --matrix matrix.gen.json --corpus corpus
echo "-- final acceptance (runs the held-out vector) --"
$PY $K/golden/golden.py replay --rust "$CLI" --matrix matrix.gen.json --corpus corpus \
    --holdout hold.gen.json --final

echo "===== diff_run — executable path (C CLI vs Rust CLI) ====="
$PY $K/differential/diff_run.py --oracle ./adler_cli_c --rust "$CLI" \
    --matrix matrix.gen.json --ledger /dev/null

echo "===== perf_gate — main's, with --floor-ms measurement honesty (5 MB workload) ====="
$PY $K/perf/perf_gate.py --oracle ./adler_cli_c --rust "$CLI" --matrix perf.gen.json --repeats 5

echo "===== diff-fuzz — small-input space (complements the vector suite) ====="
$PY $K/diff-fuzz/diff_fuzz.py --oracle ./adler_cli_c --rust "$CLI" \
    --matrix matrix.gen.json --seed 0 --iterations 500

echo "===== progress — ingest the harness --json reports to auto-advance gates ====="
$PY $K/differential/diff_run.py --oracle ./adler_cli_c --rust "$CLI" \
    --matrix matrix.gen.json --ledger /dev/null --json > reports/adler32.json
$PY $K/diff-fuzz/diff_fuzz.py --oracle ./adler_cli_c --rust "$CLI" \
    --matrix matrix.gen.json --seed 0 --iterations 500 --json > reports/adler32.fuzz.json
$PY $K/unsafe-audit/audit_unsafe.py rust/src --json > reports/adler32.unsafe.json
mkdir -p rf ff uf && cp reports/adler32.json rf/adler32.json \
   && cp reports/adler32.fuzz.json ff/adler32.json && cp reports/adler32.unsafe.json uf/adler32.json
$PY $K/progress/progress.py --file progress.gen.json init --modules adler32
$PY $K/progress/progress.py --file progress.gen.json set adler32 ported
$PY $K/progress/progress.py --file progress.gen.json ingest --diff-json rf/adler32.json
$PY $K/progress/progress.py --file progress.gen.json ingest --fuzz-json ff/adler32.json
$PY $K/progress/progress.py --file progress.gen.json set adler32 sanitized
$PY $K/progress/progress.py --file progress.gen.json ingest --unsafe-json uf/adler32.json
$PY $K/progress/progress.py --file progress.gen.json show
rm -rf rf ff uf

echo ""
echo "===== EXIT TEST COMPLETE — the port cleared every gate ====="
echo "The overflow was caught by BOTH library differentials and ledgered as a"
echo "fix-of-C-defect; scan_c_flaws and diff-fuzz found nothing (the bug is"
echo "arithmetic / large-input) — the gates divide labor, they are not redundant."
