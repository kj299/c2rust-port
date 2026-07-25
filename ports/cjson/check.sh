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
#   5. unsafe-audit       : zero undocumented unsafe (the core FORBIDS unsafe)
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
for m in scalar-parse string-parse buffer-plumbing recursive-core; do
  cp "$HERE/reports/fuzz/alloc-node.json" "$HERE/reports/fuzz/$m.json"
done

echo "===== 5. unsafe-audit over the rust workspace ====="
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates"

echo "===== 6. progress — ingest the stamped reports (multi-rung) ====="
( cd "$KIT"   # ingest verifies report provenance against THIS repo's HEAD
  "$PY" harnesses/progress/progress.py --file "$HERE/progress.json" \
      ingest \
      --diff-json "$HERE"/reports/*.json \
      --fuzz-json "$HERE"/reports/fuzz/*.json
  "$PY" harnesses/progress/progress.py --file "$HERE/progress.json" show )

echo ""
echo "===== cJSON PORT GATE COMPLETE — ported modules differential-green ====="
