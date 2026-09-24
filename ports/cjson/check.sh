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

echo "===== 0. declared controls — every one in CLAUDE.md's table must RUN here ====="
# LESSONS #31: the mutation sweep proves each gate REFUSES, and probe-coverage
# proves each module is PROBED, but nothing asked whether a declared control is
# invoked at all. Three of six were not (supply-chain, c-flaw-scan, threat-model
# — two of them "hard fail"), and every one still passed the sweep, because a
# sweep measures a harness's self-test, not its use. This check reads the control
# table and fails if the gate below never calls one.
"$PY" "$KIT/harnesses/control-coverage/check_controls.py" \
    --controls "$KIT/CLAUDE.md" --gate "$HERE/check.sh"

echo "===== 0b. Phase-0 controls — re-run against the C actually ported ====="
# The flaw scan is a Phase-0 artifact, but the C in scope GROWS as modules land:
# module 9 pulled cJSON_Utils.c in, and its 8 copy-sink sites were never triaged
# because nobody re-ran the scan (LESSONS #31). Re-run it every gate, over every
# vendored C file, so a newly-ported source cannot arrive un-triaged.
"$PY" "$KIT/harnesses/c-flaw-scan/scan_c_flaws.py" "$HERE/c" | tail -4
"$PY" "$KIT/harnesses/threat-model/check_threat_model.py" "$HERE/THREAT-MODEL.md"
# LESSONS #34 (mechanizing #26): every exported symbol must be accounted for in
# API-COVERAGE.md — module 9 shipped DONE with two of cJSON_Utils.h's 14 public
# symbols never ported and never gated, because #26 was prose in a playbook.
#
# BOTH headers, one manifest, one ratchet (LESSONS #35). This ran over
# cJSON_Utils.h alone at first, which made it green while 35 of the BASE
# library's entry points sat ungated — the gate's own scope was the next place
# the hole moved to. `unported` rows and the declared ceiling in the manifest
# keep that number honest and stop it growing.
"$PY" "$KIT/harnesses/api-coverage/check_api.py" \
    --header "$HERE/c/cJSON.h" --header "$HERE/c/cJSON_Utils.h" \
    --manifest "$HERE/API-COVERAGE.md"

echo "===== 1. oracle (build + validate all vectors against C) ====="
bash "$HERE/oracle/run.sh" > /dev/null
echo "oracle locked"

echo "===== 1b. probe-then-port — transcripts pinned, tests generated ====="
# Module expectations are GENERATED from the C's observed bytes
# (harnesses/probe/probe.py, LESSONS #17 mechanized as LESSONS #21): verify
# fails closed on oracle drift, a tampered transcript, or a hand-edited/stale
# generated test file. The generated tests themselves run under `cargo test`
# in step 2.
PROBE_SETS=(quirks plumbing builder utils access construct set seq place opts parent)
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

echo "----- module 10 (dom-access): the five accessor entry points -----"
# cJSON_GetObjectItem (CASE-INSENSITIVE), HasObjectItem, GetArrayItem,
# GetStringValue, GetNumberValue — one `access` mode exercising all five per
# input, because their contracts interlock (the value accessors are fed the
# lookup RESULTS, NULL included). Chosen as the first of the 35 unported
# cJSON.h entry points because you need accessors to OBSERVE what the mutation
# API does, so this is the dependency root, not just the easy one.
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-access.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/dom-access.json"

echo "----- module 11 (dom-construct): the twelve constructor entry points -----"
# cJSON_CreateFalse/Bool/Raw, the four typed-array constructors, and the five
# Add*ToObject helpers — one `construct` mode exercising all twelve per input.
#
# Five of these rows ASSERT a ledgered divergence rather than a match: the C's
# cJSON_CreateNumber converts a NaN to int, which is UNDEFINED behavior and
# answers INT_MIN on x86-64 but 0 on AArch64. The port takes Rust's defined
# saturating cast (0). This matrix is the finite assertion against SHIPPED
# cJSON — it fails if that divergence ever stops happening — while the fuzzer
# below uses the corrected oracle, because "every NaN" is not a set to pin
# (LESSONS #28).
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-construct.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/dom-construct.json"

echo "----- module 12 (dom-mutate-set): the two in-place setters -----"
# This block is what makes the setter hazards EXECUTED rather than read
# (LESSONS #38): MUTATION-API-SPIKE.md reasoned about both functions and got one
# of them wrong, and its evidence table now labels every hazard `ran:` or `read`
# for that reason.
# cJSON_SetValuestring and cJSON_SetNumberHelper, in one `set` mode. Ten of
# these rows ASSERT ledgered divergences rather than matches, in two classes:
#   * cJSON_SetNumberHelper writes valueint/valuedouble with NO TYPE CHECK, so
#     the C leaves a cJSON_String node carrying a number (CWE-843). The port
#     cannot represent that state, so it does nothing.
#   * the same NaN -> int UB cJSON_CreateNumber has, at the second of the two
#     sites carrying that cast.
# Both classes are predicate-defined, so the finite assertion lives HERE against
# shipped cJSON and the fuzzer below uses the corrected oracle (LESSONS #28).
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-set.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/dom-mutate-set.json"

echo "----- module 13 (dom-mutate-remove): Detach + Delete, as a PROGRAM -----"
# The six removal entry points, driven by the `seq` mode: stdin is a document
# plus a list of ops, and the descriptor is emitted after EVERY step. That is
# the point. cJSON's detach rewires a doubly-linked child list whose
# `child->prev` is its last-item cache; a bad relink is invisible until a LATER
# operation consumes it (MUTATION-API-SPIKE.md H1b), so a single-shot mode would
# report MATCH on exactly the bug this module exists to rule out. The `app` op is
# that later operation, and it is in the mode because an append is the only thing
# that CONSUMES the cache (LESSONS #39).
#
# No ledgered rows: unlike modules 11 and 12 this port matches shipped cJSON on
# every one of these entry points, so the fuzzer below uses the PRISTINE oracle.
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-seq.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/dom-mutate-remove.json"

echo "----- module 14 (dom-mutate-place): Insert + Replace, same PROGRAM -----"
# cJSON_InsertItemInArray and cJSON_ReplaceItemIn{Array,Object,ObjectCaseSensitive},
# as four more `seq` opcodes so they COMPOSE with the removal ops rather than
# being tested beside them. cJSON_ReplaceItemViaPointer is out-of-scope for the
# same reason as its Detach twin, and worse: it frees the item after relinking,
# so a wrong parent leaves another tree holding freed memory.
#
# No ledger entry: this surface matches shipped cJSON everywhere, including the
# two behaviors that read like bugs and are not (an insert past the end appends;
# a case-insensitive object replace rewrites the member's key to the lookup
# spelling). Both are pinned as probes rather than argued about.
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-place.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/dom-mutate-place.json"

echo "----- module 15 (entry-opts): the four *WithOpts / buffered entry points -----"
# cJSON_ParseWithOpts, cJSON_ParseWithLengthOpts, cJSON_PrintBuffered and
# cJSON_PrintPreallocated, all four behind the `opts` mode.
#
# Two things this module put on the compared contract that nothing else did:
#
#  1. `*return_parse_end`. The error TEXT stays a documented divergence, but the
#     parse-end OFFSET is the *WithOpts pair's entire distinct behavior, so
#     leaving it off would have gated nothing (LESSONS #26). It found a real
#     port divergence immediately: cJSON's parse_string rewinds to a pointer it
#     initializes before validating anything, so a non-quote object key reports
#     the offset PAST it. Latent since module 3, invisible until now.
#
#  2. the `ensure` ACCOUNTING. The port deliberately designed cJSON's
#     printbuffer bookkeeping away in module 4 because `Vec` growth subsumes it
#     — correct for every growable printer, and wrong the moment
#     cJSON_PrintPreallocated made the accounting itself the success predicate.
#     print.rs now mirrors all fifteen ensure() call sites.
#
# The 5 opts-prealloc-* rows ASSERT the ledgered partial-write divergence still
# diverges from shipped cJSON; the fuzzer below uses the corrected oracle.
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-opts.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/entry-opts.json"

echo "----- module 16 (dom-add-parent): the non-container parent -----"
# cJSON's add_item_to_array guards a NULL item, a NULL parent and
# self-reference -- never that the parent is a CONTAINER. So every public Add*
# entry point hangs a child off a number and gives an object a NULL-keyed
# member. The port cannot represent either (Value::Array is the only variant
# with room for a child; an Object entry always has a key), so it answers false.
#
# Three earlier modules declined this class and said so in writing. The reason
# it took four attempts is that the port's three comparison surfaces are ALL
# blind to it: print ignores a child hung off a non-container, cJSON_Compare
# calls a malformed node equal to a clean one, and cJSON_Duplicate copies the
# hung child. So the `parent` mode's descriptor reports the CONTAINER VIEW
# (GetArraySize/GetArrayItem) and the two object lookups SEPARATELY -- the
# case-sensitive one stops at a NULL key and the case-insensitive one does not,
# which is how a NULL-keyed member hides every member after it (LESSONS #39).
#
# 12 ledgered rows assert the divergence still happens against shipped cJSON;
# the 16 matching rows prove it is no wider than claimed. The fuzzer below uses
# the corrected oracle.
"$PY" "$KIT/harnesses/differential/diff_run.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --matrix "$HERE/oracle/matrix-parent.json" --ledger "$HERE/DIVERGENCES.md" \
    --json > "$HERE/reports/dom-add-parent.json"

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
# The CORRECTED oracle — the vendored C with its two known defects fixed. Built
# once here because TWO modes now need it (LESSONS #28: a predicate-defined
# intentional divergence cannot be fingerprint-pinned for a fuzzer, so those
# modes fuzz against a C that shares the port's fix and every finding is real):
#   patch     : cJSON_Utils.c's ~0/~1 pointer decode  (utils-tilde-*)
#   construct : cJSON.c's NaN -> int conversion       (create-number-nan-*)
#   set       : the same cast in cJSON_SetNumberHelper, plus its missing type
#               check                                 (set-number-nan-*, set-*-type-confusion)
# Every other mode fuzzes against the PRISTINE oracle.
bash "$HERE/oracle/build_fixed.sh" > /dev/null
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
# access mode: fuzz the accessor surface. Its own matrix is the seed corpus, so
# the fuzzer mutates the "<key>\t<index>\n<json>" framing too — a malformed
# index or a missing tab has to normalize identically on both sides before
# cJSON_GetArrayItem ever sees an int.
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle" --rust "$RUST_DRIVER" \
    --args access --matrix "$HERE/oracle/matrix-access.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/dom-access.json"
# construct mode: fuzz the twelve constructors against the CORRECTED oracle (see
# the build_fixed.sh note above). Its own matrix seeds the corpus, so the fuzzer
# mutates the "<count>\t<name>\t<raw>\n<payload>" framing as well as the element
# bytes — and those seeds include stdin_b64 rows carrying NaN bit patterns that
# a UTF-8 seed string could not spell at all (LESSONS #36).
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle_fixed" --rust "$RUST_DRIVER" \
    --args construct --matrix "$HERE/oracle/matrix-construct.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/dom-construct.json"
# set mode: fuzz the two setters against the CORRECTED oracle as well — the
# `set` mode's divergences are the same shape as `construct`'s (every NaN, and
# now every non-number target), so the pristine oracle would report an endless
# stream of already-known differences and drown a real one. Its matrix seeds the
# corpus, so the fuzzer mutates the "<bits>\t<key>\t<newstr>\n<json>" framing as
# well as the document — including stdin_b64 rows whose replacement carries an
# interior NUL or a lone 0x80-0xFF byte (LESSONS #36).
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle_fixed" --rust "$RUST_DRIVER" \
    --args set --matrix "$HERE/oracle/matrix-set.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/dom-mutate-set.json"
# seq mode: fuzz the removal surface against the CORRECTED oracle. It used the
# PRISTINE one while `app`/`ins`/`rep` refused a non-array target and the mode
# therefore had no intentional divergence. Lifting that restriction (module 16)
# made the statement false: a fuzzer picking selectors from a mutated document
# names a scalar or an object constantly, and every one of those is the
# predicate-defined `scalar-parent-child` class, which has no finite fingerprint
# set (LESSONS #28). Its own matrix seeds the corpus, so the fuzzer mutates the
# document, the op grammar and the "<op>\t<sel>\t<arg>" framing independently.
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle_fixed" --rust "$RUST_DRIVER" \
    --args seq --matrix "$HERE/oracle/matrix-seq.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/dom-mutate-remove.json"
# ...and the same mode seeded from the PLACEMENT matrix, so the fuzzer mutates
# programs whose ops are inserts and replaces rather than detaches. Same mode,
# different seed corpus, different reachable states -- and the corrected oracle
# for the same reason as above, with one route of its own: `ins` falls through
# to the STATIC add_item_to_array past both entry points patched for `app`, so
# make_fixed_core.py patches cJSON_InsertItemInArray separately.
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle_fixed" --rust "$RUST_DRIVER" \
    --args seq --matrix "$HERE/oracle/matrix-place.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/dom-mutate-place.json"
# opts mode: fuzz the four options entry points against the CORRECTED oracle —
# the partial-write divergence is predicate-defined (EVERY buffer length between
# "the first ensure fails" and the boundary triggers it), so the pristine oracle
# would report a steady stream of known differences and drown a real one
# (LESSONS #28). Its matrix seeds the corpus, so the fuzzer mutates the
# "<flags>\t<prebuffer>\t<prealloc>\n<json>" framing as well as the document —
# which is what sweeps the buffer length across and past the boundary, and what
# sends negative and absurd lengths into both printers' guards.
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle_fixed" --rust "$RUST_DRIVER" \
    --args opts --matrix "$HERE/oracle/matrix-opts.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/entry-opts.json"
# parent mode: fuzz the non-container parent against the CORRECTED oracle --
# the class is predicate-defined (EVERY non-container parent), and kind=doc lets
# the fuzzer pick the target's TYPE from the mutated document, so the pristine
# oracle would report a constant stream of known differences (LESSONS #28). Its
# matrix seeds the corpus, so the "<kind>\t<op>\t<key>\n<json>" framing is
# mutated alongside the document.
"$PY" "$KIT/harnesses/diff-fuzz/diff_fuzz.py" \
    --oracle "$HERE/oracle/cjson_oracle_fixed" --rust "$RUST_DRIVER" \
    --args parent --matrix "$HERE/oracle/matrix-parent.json" \
    --ledger "$HERE/DIVERGENCES.md" --iterations 2000 --timeout 5 \
    --json > "$HERE/reports/fuzz/dom-add-parent.json"
for m in scalar-parse string-parse buffer-plumbing recursive-core; do
  cp "$HERE/reports/fuzz/alloc-node.json" "$HERE/reports/fuzz/$m.json"
done

# module 9 (cJSON_Utils): fuzz all six modes. `patch` decodes a ~0/~1 escape in a
# Patch child key CORRECTLY (the ledgered fix), so it uses the corrected oracle
# built at the top of this section; the other five have no intentional
# divergence and fuzz against the pristine one.
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

echo "===== 4a. oracle-sanitize — the C side of the differential is OUR C too ====="
# LESSONS #40: `oracle/driver.c` + `oracle/cjson_modes.c` are ~1000 lines this
# port wrote, sizing buffers and transferring ownership by hand. A leak or an
# overread there changes no stdout, so every other gate stays green over it --
# and for fourteen modules nothing looked. Build a sanitized twin and drive
# every matrix case through it. Toolchain-optional in the same LOUD way as the
# sanitizer step: a missing compiler prints a SKIP, never a silent pass.
if [ ! -x "$HERE/oracle/build_asan.sh" ]; then
  echo "MISSING  oracle-sanitize: oracle/build_asan.sh is gone. This gate is"
  echo "         declared in CLAUDE.md's control table; a deleted build script"
  echo "         must not look like a thin toolchain."
  exit 1
elif bash "$HERE/oracle/build_asan.sh" > /dev/null 2>&1; then
  # `--matrix` takes ONE path per flag, so the glob has to become repeated
  # flags rather than a bare expansion — the first draft passed the extra paths
  # as positionals and argparse rejected the whole invocation (rc 2).
  SAN_MATRICES=()
  for m in "$HERE"/oracle/matrix*.json; do SAN_MATRICES+=(--matrix "$m"); done
  "$PY" "$KIT/harnesses/oracle-sanitize/sanitize_oracle.py" \
      --oracle "$HERE/oracle/cjson_oracle_asan" \
      "${SAN_MATRICES[@]}" --timeout 60
else
  echo "SKIP  oracle-sanitize: build_asan.sh exists but did not build (no"
  echo "      ASan-capable compiler?). The C driver was NOT checked this run."
fi

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
# The ffi crate's C-ABI shim is the only unsafe — and that sentence is a claim
# only `core`'s forbid makes true. audit_unsafe.py below would pass unsafe in
# core given a // SAFETY:; this fails if core's forbid is deleted, commented
# out, weakened to deny, or put under cfg_attr (LESSONS #46). ffi's own `//!`
# header quotes the attribute while describing core — a grep-based check reads
# that as ffi forbidding unsafe, which is the opposite of the truth.
"$PY" "$KIT/harnesses/unsafe-audit/check_forbid_unsafe.py" "$HERE/rust/crates/core"
# Every block must carry a
# // SAFETY:. Emitted per-module as a stamped report so the final gate rung
# (unsafe_audited) advances from the harness's own verdict, not by hand.
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates"
mkdir -p "$HERE/reports/unsafe"
"$PY" "$KIT/harnesses/unsafe-audit/audit_unsafe.py" "$HERE/rust/crates" --json \
    > "$HERE/reports/unsafe/alloc-node.json"
# From progress.json, not a literal — the same hand-maintained-list trap the
# sanitizer fan-out had (LESSONS #25). The audit is workspace-wide, so one
# verdict legitimately covers every tracked module; what must not be hand-kept
# is WHICH modules exist.
for m in $("$PY" -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["modules"]))' "$HERE/progress.json"); do
  [ "$HERE/reports/unsafe/$m.json" = "$HERE/reports/unsafe/alloc-node.json" ] && continue
  cp "$HERE/reports/unsafe/alloc-node.json" "$HERE/reports/unsafe/$m.json"
done

echo "===== 5b. supply-chain — the dependency surface ====="
# LESSONS #31: this control was in CLAUDE.md's table and in the mutation sweep,
# yet the port's gate never called it, so the port's dependency tree had never
# been audited at all. Toolchain-optional like the sanitizers, and for the same
# reason: absence of the tool must be LOUD, never silently green. When the tools
# ARE present the harness's own fail-closed verdict stands (no `|| true` here).
if command -v cargo-audit >/dev/null 2>&1 && command -v cargo-deny >/dev/null 2>&1; then
  bash "$KIT/harnesses/supply-chain/run_supply_chain.sh" "$HERE/rust"
  echo "supply-chain: dependency audit clean"
else
  echo "SKIP  supply-chain: cargo-audit/cargo-deny absent — the dependency audit"
  echo "      did NOT run (install: cargo install cargo-audit cargo-deny)."
  echo "      Reported every run so an unaudited dep tree cannot look green."
fi

if [ "$SAN_RAN" = "1" ]; then
  # `sanitized` is no longer hand-set (LESSONS #24): it advances in step 6 from
  # the sanitizer harness's own provenance-stamped report, exactly like the other
  # five rungs. A SKIP writes no report — and a report where nothing ran carries
  # an empty `modes_run`, which `progress.py` refuses. The claim can no longer
  # outlive the run that earned it.
  # The module list comes from progress.json, NOT a literal here. It used to be
  # hardcoded, and adding module 10 (dom-access) left it out — the gate caught it
  # (`REPLAY FAILED: dom-access stuck at fuzzed`), which is the system working,
  # but a hand-maintained list that must be edited in lockstep with another file
  # is the LESSONS #25 shape and would eventually be edited wrong in the safe
  # direction instead. The sanitizer run is workspace-wide, so every tracked
  # module is legitimately covered by this one report.
  SAN_MODULES=$("$PY" -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["modules"]))' "$HERE/progress.json")
  for m in $SAN_MODULES; do
    # skip the stem the harness itself wrote — `cp x x` is an error under set -e
    [ "$HERE/reports/sanitize/$m.json" = "$SAN_REPORT" ] && continue
    cp "$SAN_REPORT" "$HERE/reports/sanitize/$m.json"
  done
  echo "sanitizer reports emitted for every module ($SAN_MODULES)"
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
