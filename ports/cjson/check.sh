#!/usr/bin/env bash
# cJSON port — the increment gate. Runs every check the current porting state
# supports, fail-closed. This is the script CI runs; a module's progress.json
# gate may only advance if its harness passes HERE.
#
#   1. oracle locked      : build C driver, regen corpus, validate all vectors vs C
#   2. rust workspace     : fmt --check, clippy -D warnings, build --release, test
#   3. differential       : diff_run over matrix-ported.json (the modules ported
#                           so far), ledgered via ../DIVERGENCES.md
#   4. diff-fuzz          : differential fuzzing, seeds from the full matrix —
#                           live since the recursive core landed (the parse
#                           entry points now decide every non-minify input)
#   5. unsafe-audit       : every unsafe block // SAFETY:-documented (the core
#                           FORBIDS unsafe; the ffi crate's C-ABI shim is the
#                           only unsafe, and every block is audited)
#   6. progress ingest    : advance module gates from the harnesses' own stamped
#                           --json reports (provenance-verified against HEAD)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$HERE/../.."
PY="${PYTHON:-python3}"
RUST_DRIVER="$HERE/rust/target/release/rjson_driver"

echo "===== 1. oracle (build + validate all vectors against C) ====="
bash "$HERE/oracle/run.sh" > /dev/null
echo "oracle locked"

echo "===== 2. rust workspace (fmt / clippy / build / test) ====="
( cd "$HERE/rust"
  cargo fmt --all -- --check
  cargo clippy --all-targets --release -- -D warnings
  cargo build --release --quiet
  cargo test --all --quiet )
echo "rust workspace clean"

echo "===== 2b. FFI ABI differential — the Rust .so is drop-in for the C .so ====="
bash "$HERE/ffi/build.sh"                       # libcjson_c.so (pristine cJSON + shims)
"$PY" "$KIT/harnesses/library-differential/lib_diff.py" \
    --c-lib "$HERE/ffi/libcjson_c.so" \
    --rust-lib "$HERE/rust/target/release/libcjson_rs.so" \
    --vectors "$HERE/ffi/vectors.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports_ffi.json" || { cat "$HERE/reports_ffi.json"; exit 1; }
echo "FFI ABI differential clean (Rust cdylib == C .so)"

echo "===== 3. differential — Rust vs C over the ported modules ====="
mkdir -p "$HERE/reports"
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-ported.json" --ledger "$HERE/DIVERGENCES.md"
# the same run, as a stamped report per attested module (both modules' observable
# surface IS this scalar matrix; the stems name the modules progress tracks)
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-ported.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/alloc-node.json"
cp "$HERE/reports/alloc-node.json" "$HERE/reports/scalar-parse.json"
cp "$HERE/reports/alloc-node.json" "$HERE/reports/string-parse.json"
cp "$HERE/reports/alloc-node.json" "$HERE/reports/buffer-plumbing.json"
cp "$HERE/reports/alloc-node.json" "$HERE/reports/recursive-core.json"
cp "$HERE/reports/alloc-node.json" "$HERE/reports/entry-minify.json"

echo "----- module 6 (dom): dup + dup-eq differentials -----"
# dup: parse -> Duplicate -> print (must byte-match a plain round-trip)
# dup-eq: a value compares equal to its duplicate ... EXCEPT the C quirks
# (inf never equals itself; duplicate keys never compare equal), which the
# port reproduces — so Rust must MATCH C's true/false, checked here.
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-dup.json" --ledger "$HERE/DIVERGENCES.md"
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-dupeq.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/dom.json"

echo "===== 4. diff-fuzz — differential fuzzing, Rust vs C ====="
mkdir -p "$HERE/reports/fuzz"
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --args print-unformatted --matrix "$HERE/oracle/matrix.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/alloc-node.json"
# minify mode too — the #338 site, and where the fuzzer found the escape-parity
# quirk. Both modes must stay clean.
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --args minify --matrix "$HERE/oracle/matrix.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/entry-minify.json"
# dom mode: fuzz the Compare+Duplicate invariant (dup-eq)
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --args dup-eq --matrix "$HERE/oracle/matrix.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/dom.json"
for m in scalar-parse string-parse buffer-plumbing recursive-core; do
  cp "$HERE/reports/fuzz/alloc-node.json" "$HERE/reports/fuzz/$m.json"
done

echo "===== 4b. miri — UB check over the FFI crate's unsafe (toolchain-optional) ====="
# The ffi crate is the port's ENTIRE memory-safety risk surface, so this is where
# UB detection matters. Toolchain-optional like the kit's skeleton gate: SKIPs
# cleanly without nightly+miri, runs for real when present. Verified fail-closed:
# injecting an out-of-bounds read into the FFI tests makes miri exit nonzero
# (LESSONS #6 — a sanitizer that can't fail proves nothing; LESSONS #18 — and a
# gate that never RAN must not advance the rung either).
if cargo +nightly miri --version >/dev/null 2>&1; then
  ( cd "$HERE/rust" && cargo +nightly miri test -p cjson_ffi -p cjson_core --quiet )
  echo "miri: no UB in the unsafe FFI surface (or the safe core)"
  MIRI_RAN=1
else
  echo "SKIP  miri: no nightly+miri toolchain (install: rustup toolchain install nightly --component miri)"
  MIRI_RAN=0
fi

echo "===== 5. unsafe-audit over the rust workspace ====="
# The ffi crate's C-ABI shim is the only unsafe; every block must carry a
# // SAFETY:. Emitted per-module as a stamped report so the final gate rung
# (unsafe_audited) advances from the harness's own verdict, not by hand.
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates"
mkdir -p "$HERE/reports/unsafe"
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates" --json \
    > "$HERE/reports/unsafe/alloc-node.json"
for m in scalar-parse string-parse buffer-plumbing recursive-core dom entry-minify; do
  cp "$HERE/reports/unsafe/alloc-node.json" "$HERE/reports/unsafe/$m.json"
done

if [ "$MIRI_RAN" = "1" ]; then
  # `sanitized` has no --json harness, so it is set explicitly — and ONLY when
  # miri actually ran (never on a SKIP: an unrun gate must not advance).
  for m in alloc-node scalar-parse string-parse buffer-plumbing recursive-core dom entry-minify; do
    "$PY" "$KIT/harnesses/progress/progress.py" --file "$HERE/progress.json" set "$m" sanitized >/dev/null
  done
  echo "progress: sanitized gate set for every module (miri ran)"
fi

echo "===== 6. progress — ingest the stamped reports (multi-rung) ====="
( cd "$KIT"   # ingest verifies report provenance against THIS repo's HEAD
  "$PY" harnesses/progress/progress.py --file "$HERE/progress.json" \
      ingest \
      --diff-json "$HERE"/reports/*.json \
      --fuzz-json "$HERE"/reports/fuzz/*.json \
      --unsafe-json "$HERE"/reports/unsafe/*.json
  "$PY" harnesses/progress/progress.py --file "$HERE/progress.json" show )

echo ""
echo "===== cJSON PORT GATE COMPLETE — ported modules differential-green ====="
