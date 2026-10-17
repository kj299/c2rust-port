// cargo-fuzz target for EVERY driver mode `cjson_core::modes::run` dispatches —
// the whole stdin surface the differential driver exposes, utils and the
// mutation programs (`seq`) included. Scaffolded from
// porting-kit/harnesses/fuzz/fuzz_target.template.rs.
//
// Same contract as `parse_print`: never panic, abort, or exhibit UB on
// arbitrary bytes. The first byte picks the mode; the rest is stdin, framed
// however that mode frames it — so the fuzzer learns each mode's framing from
// coverage, and check.sh seeds it with every matrix case as `[mode, stdin...]`.
#![no_main]

use libfuzzer_sys::fuzz_target;

/// Every mode `modes::run` answers, in a FIXED order: check.sh's seeding writes
/// the index of a case's mode as the first byte, so reordering this list
/// re-labels the committed seeds' meaning (they are regenerated each run, but
/// a crash artifact's first byte is only meaningful against this order).
const MODES: &[&str] = &[
    "print",
    "print-unformatted",
    "roundtrip",
    "minify",
    "dup",
    "dup-eq",
    "build",
    "query",
    "access",
    "construct",
    "set",
    "seq",
    "opts",
    "parent",
    "parse",
    "ptr",
    "ptr-cs",
    "patch",
    "patch-cs",
    "merge",
    "merge-cs",
    "genmerge",
    "genmerge-cs",
    "genpatch",
    "genpatch-cs",
    "findptr",
    "findptr-cs",
    "addpatch",
    "sort",
    "sort-cs",
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let mode = MODES[usize::from(selector) % MODES.len()];
    let _ = cjson_core::modes::run(mode, input);
});
