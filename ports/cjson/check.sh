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

echo "===== 1b. probe-then-port — transcripts pinned, tests generated ====="
# Module expectations are GENERATED from the C's observed bytes
# (harnesses/probe/probe.py, LESSONS #17 mechanized as LESSONS #21): verify
# fails closed on oracle drift, a tampered transcript, or a hand-edited/stale
# generated test file. The generated tests themselves run under `cargo test`
# in step 2.
PROBE_SETS=(quirks plumbing builder utils)
PROBE_FILES=()
for set in "${PROBE_SETS[@]}"; do
  PROBE_FILES+=("$HERE/oracle/probes-$set.json")
  "$PY" "$KIT/harnesses/probe/probe.py" verify \
      --probes "$HERE/oracle/probes-$set.json" \
      --oracle "$HERE/oracle/cjson_oracle" \
      --transcript "$HERE/oracle/probes-$set.transcript.json" \
      --out "$HERE/rust/crates/core/tests/probes_$set.rs"
done
# ...and the gate ABOVE those gates (LESSONS #23): verifying the probe files that
# EXIST says nothing about a module that has none. Coverage reads the module list
# from progress.json itself, so a module the gates track but nobody probed is red.
"$PY" "$KIT/harnesses/probe/probe.py" coverage \
    --probes "${PROBE_FILES[@]}" --progress "$HERE/progress.json"

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

echo "----- module 8 (ffi-builder): builder + query differentials -----"
# build:  stdin is a VARIANT NAME; the observable result is the document the
#         Create/Add API produced.
# query:  every parse-testable corpus document looked up by key, described via
#         the Is* predicates and the struct fields (type/valueint/valuestring)
#         a C caller reads straight off the pointer.
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-builder.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/ffi-builder.json"

echo "----- module 9 (cJSON_Utils): pointer / patch / merge / sort differentials -----"
# JSON Pointer (RFC 6901), Patch (6902), Merge-Patch (7396), object sort. The 3
# utils-tilde-* rows in the matrix ASSERT the ledgered decode fix still diverges
# from shipped cJSON; everything else matches byte-for-byte. One report, stamped
# per utils module (the surface is shared, as with the scalar matrix above).
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-utils.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/utils-pointer.json"
cp "$HERE/reports/utils-pointer.json" "$HERE/reports/utils-patch.json"
cp "$HERE/reports/utils-pointer.json" "$HERE/reports/utils-sort.json"

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
# query mode: fuzz the accessor/predicate surface over mutated documents
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --args query --matrix "$HERE/oracle/matrix-builder.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/ffi-builder.json"
for m in scalar-parse string-parse buffer-plumbing recursive-core; do
  cp "$HERE/reports/fuzz/alloc-node.json" "$HERE/reports/fuzz/$m.json"
done

# module 9 (cJSON_Utils): fuzz all six modes. `patch` decodes a ~0/~1 escape in a
# Patch child key CORRECTLY (the ledgered fix), so fuzzing it against the PRISTINE
# oracle would rediscover that intentional divergence for every ~escaped key — a
# predicate-defined divergence class is not a finite set to pin (LESSONS #28). So
# `patch` fuzzes against a CORRECTED oracle (build_fixed.sh: pristine cJSON + the
# one-line decode fix), where both sides decode correctly and any divergence is a
# REAL port bug. The other five modes have no intentional divergence and fuzz
# against the pristine oracle.
bash "$HERE/oracle/build_fixed.sh" > /dev/null
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --args ptr --matrix "$HERE/oracle/matrix-utils.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/utils-pointer.json"
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle_fixed" --rust "$RUST_DRIVER" \
    --args patch --matrix "$HERE/oracle/matrix-utils.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/utils-patch.json"
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --args sort --matrix "$HERE/oracle/matrix-utils.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/utils-sort.json"
# merge / genmerge / genpatch share the utils-patch surface (RFC 6902/7396); run
# them fail-closed — a finding exits nonzero and aborts under `set -e`.
for um in merge genmerge genpatch; do
  "$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
      --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
      --args "$um" --matrix "$HERE/oracle/matrix-utils.json" \
      --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 > /dev/null
done

echo "===== 4b. sanitizers — miri (UB) + asan (FFI memory), toolchain-optional ====="
# The ffi crate is the port's ENTIRE memory-safety risk surface, so this is where
# UB detection matters. Runs through the KIT's sanitizer harness, not a hand-rolled
# cargo line: the port duplicating that invocation is exactly why the harness's
# `ubsan` mode could ship permanently broken and nobody noticed (LESSONS #22).
# `all` = miri + asan in ONE run, so the emitted report names every checker that
# actually ran (LESSONS #24) instead of under-reporting a second, unrecorded pass.
# Toolchain-optional like the kit's skeleton gate; verified fail-closed by
# injecting an out-of-bounds read into the FFI tests (miri exits nonzero —
# LESSONS #6; and a gate that never RAN must not advance the rung — LESSONS #18).
mkdir -p "$HERE/reports/sanitize"
SAN_REPORT="$HERE/reports/sanitize/alloc-node.json"
rm -f "$SAN_REPORT"          # never let a previous run's report stand in for this one
if cargo +nightly miri --version >/dev/null 2>&1; then
  bash "$KIT/harnesses/sanitizers/run_sanitizers.sh" all "$HERE/rust" \
      --json "$SAN_REPORT" -- -p cjson_ffi -p cjson_core
  echo "sanitizers: no UB (miri) and no memory errors (asan) in the unsafe surface"
  SAN_RAN=1
elif rustc +nightly --version >/dev/null 2>&1; then
  bash "$KIT/harnesses/sanitizers/run_sanitizers.sh" asan "$HERE/rust" \
      --json "$SAN_REPORT" -- -p cjson_ffi -p cjson_core
  echo "sanitizers: asan clean (miri absent — install: rustup component add --toolchain nightly miri)"
  SAN_RAN=1
else
  echo "SKIP  sanitizers: no nightly toolchain (no report written, so the"
  echo "      sanitized rung cannot advance — an unrun gate proves nothing)"
  SAN_RAN=0
fi

echo "===== 5. unsafe-audit over the rust workspace ====="
# The ffi crate's C-ABI shim is the only unsafe; every block must carry a
# // SAFETY:. Emitted per-module as a stamped report so the final gate rung
# (unsafe_audited) advances from the harness's own verdict, not by hand.
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates"
mkdir -p "$HERE/reports/unsafe"
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates" --json \
    > "$HERE/reports/unsafe/alloc-node.json"
for m in scalar-parse string-parse buffer-plumbing recursive-core dom entry-minify ffi-builder utils-pointer utils-patch utils-sort; do
  cp "$HERE/reports/unsafe/alloc-node.json" "$HERE/reports/unsafe/$m.json"
done

if [ "$SAN_RAN" = "1" ]; then
  # `sanitized` is no longer hand-set (LESSONS #24): it advances in step 6 from
  # the sanitizer harness's own provenance-stamped report, exactly like the other
  # five rungs. A SKIP writes no report — and a report where nothing ran carries
  # an empty `modes_run`, which `progress.py` refuses. The claim can no longer
  # outlive the run that earned it.
  for m in scalar-parse string-parse buffer-plumbing recursive-core dom entry-minify ffi-builder utils-pointer utils-patch utils-sort; do
    cp "$SAN_REPORT" "$HERE/reports/sanitize/$m.json"
  done
  echo "sanitizer reports emitted for every module"
fi

echo "===== 6. progress — the ladder must be EARNED from this run's reports ====="
# The committed progress.json already sits at the top rung, so a plain ingest
# advances nothing and proves nothing: a rung that quietly stopped being provable
# would look identical to one that still is. So first REPLAY the ingest into a
# scratch copy seeded at `ported` — every module must climb to unsafe_audited
# from the reports this run just produced, or the gate fails (LESSONS #24: a
# claim must not outlive the evidence that earned it).
REPLAY="$(mktemp -d)/progress-replay.json"
"$PY" -c "
import json, sys
src = json.load(open('$HERE/progress.json'))
json.dump({'modules': {m: 'ported' for m in src['modules']}}, open('$REPLAY', 'w'))
"
( cd "$KIT"
  "$PY" harnesses/progress/progress.py --file "$REPLAY" ingest \
      --diff-json "$HERE"/reports/*.json \
      --fuzz-json "$HERE"/reports/fuzz/*.json \
      --sanitize-json "$HERE"/reports/sanitize/*.json \
      --unsafe-json "$HERE"/reports/unsafe/*.json >/dev/null )
"$PY" -c "
import json, sys
st = json.load(open('$REPLAY'))['modules']
stuck = {m: g for m, g in st.items() if g != 'unsafe_audited'}
if stuck:
    print('REPLAY FAILED: these modules could not be re-earned from this run\'s '
          'reports alone:', file=sys.stderr)
    for m, g in sorted(stuck.items()):
        print(f'  {m}: stuck at {g}', file=sys.stderr)
    sys.exit(1)
print(f'replay: all {len(st)} module(s) re-earned every rung from this run\'s reports')
"
rm -rf "$(dirname "$REPLAY")"

echo "----- and the committed table -----"
( cd "$KIT"   # ingest verifies report provenance against THIS repo's HEAD
  "$PY" harnesses/progress/progress.py --file "$HERE/progress.json" \
      ingest \
      --diff-json "$HERE"/reports/*.json \
      --fuzz-json "$HERE"/reports/fuzz/*.json \
      --sanitize-json "$HERE"/reports/sanitize/*.json \
      --unsafe-json "$HERE"/reports/unsafe/*.json
  "$PY" harnesses/progress/progress.py --file "$HERE/progress.json" show )

echo ""
echo "===== cJSON PORT GATE COMPLETE — ported modules differential-green ====="
