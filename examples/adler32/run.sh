#!/usr/bin/env bash
# The porting kit's v1.0 exit test, as a reproducible script: a tiny C library
# (adler32, with a textbook latent overflow bug) driven through every gate against
# its safe+correct Rust port. Needs a C compiler, cargo, and python3 — NOT part of
# `make check-kit` (that stays toolchain-free); this is the end-to-end demo.
#
#   ./run.sh          # build + drive every gate; nonzero exit if any gate fails
#
# KIT points at the kit's harnesses (default: two levels up).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
KIT="${KIT:-$here/../../harnesses}"
cd "$here"
fail=0
step() { echo; echo "== $* =="; }
check() { if [ "$1" -eq 0 ]; then echo "  gate: PASS"; else echo "  gate: FAIL (exit $1)"; fail=1; fi; }

step "build C (.so for lib_diff, CLI for the executable gates)"
cc -O2 -shared -fPIC -o libadler_c.so c/adler32.c
cc -O2 -o adler_cli_c c/adler_cli.c c/adler32.c
C=./adler_cli_c

step "build Rust (cdylib + CLI, release)"
( cd rust && cargo build --release --quiet )
R=rust/target/release/radler_cli
RLIB=rust/target/release/libradler.so

step "cargo test — port correctness on known vectors"
( cd rust && cargo test --release --quiet ); check $?

step "Phase 0 — scan_c_flaws on the C library"
# Expect 0 sink findings: the bug here is ARITHMETIC (overflow), not a grep-able
# sink — which is exactly why the differential + fuzzing gates exist.
python3 "$KIT/c-flaw-scan/scan_c_flaws.py" c/adler32.c; check $?

step "unsafe-audit — the Rust port's FFI layer"
python3 "$KIT/unsafe-audit/audit_unsafe.py" rust/src/; check $?

step "lib_diff — C .so vs Rust cdylib, per function (the library differential)"
# The 10 000-byte vector DIVERGEs (the C overflows); DIVERGENCES.md pins it as an
# intentional fix-of-C-defect, so this run is clean.
python3 "$KIT/library-differential/lib_diff.py" --c-lib ./libadler_c.so \
    --rust-lib "$RLIB" --vectors vectors.json --ledger DIVERGENCES.md; check $?

step "golden — capture the C oracle (validate + hold a vector back), replay the Rust"
python3 "$KIT/golden/golden.py" capture --oracle "$C" --matrix pub.json \
    --corpus corpus --holdout hold.json --validate; check $?
python3 "$KIT/golden/golden.py" replay --rust "$R" --matrix pub.json --corpus corpus; check $?
python3 "$KIT/golden/golden.py" replay --rust "$R" --matrix pub.json --corpus corpus \
    --holdout hold.json --final; check $?

step "diff_run — C CLI vs Rust CLI over the matrix (executable path)"
python3 "$KIT/differential/diff_run.py" --oracle "$C" --rust "$R" \
    --matrix matrix.json --ledger /dev/null; check $?

step "perf-gate — Rust CLI vs C CLI (fail if >1.3x the C median)"
python3 -c "import json; json.dump([{'name':'bulk','args':[],'stdin':'a'*500000}], open('perf.json','w'))"
python3 "$KIT/perf-gate/perf_gate.py" --oracle "$C" --rust "$R" \
    --matrix perf.json --repeats 7 --warmup 2; check $?

step "diff-fuzz — same mutated stdin to both, 2000 iters"
python3 "$KIT/diff-fuzz/diff_fuzz.py" --oracle "$C" --rust "$R" \
    --matrix matrix.json --seed 0 --iterations 2000; check $?

step "progress — drive the module up the gate ladder from the harness --json reports"
mkdir -p rep/diff rep/fuzz rep/unsafe
python3 "$KIT/library-differential/lib_diff.py" --c-lib ./libadler_c.so --rust-lib "$RLIB" \
    --vectors vectors.json --ledger DIVERGENCES.md --json > rep/diff/adler32.json
python3 "$KIT/diff-fuzz/diff_fuzz.py" --oracle "$C" --rust "$R" --matrix matrix.json \
    --seed 0 --iterations 500 --json > rep/fuzz/adler32.json
python3 "$KIT/unsafe-audit/audit_unsafe.py" rust/src/ --json > rep/unsafe/adler32.json
P="$KIT/progress/progress.py"; F=progress.json
python3 "$P" --file "$F" init --modules adler32 >/dev/null
python3 "$P" --file "$F" set adler32 ported >/dev/null
python3 "$P" --file "$F" ingest --diff-json rep/diff/adler32.json
python3 "$P" --file "$F" ingest --fuzz-json rep/fuzz/adler32.json
python3 "$P" --file "$F" set adler32 sanitized >/dev/null   # no sanitizer in this demo → manual
python3 "$P" --file "$F" ingest --unsafe-json rep/unsafe/adler32.json
python3 "$P" --file "$F" show; check $?

echo
if [ "$fail" -eq 0 ]; then echo "EXIT TEST: all gates PASS"; else echo "EXIT TEST: a gate FAILED"; fi
exit "$fail"
