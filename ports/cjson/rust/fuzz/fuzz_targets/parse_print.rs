// cargo-fuzz target for the `parse`/`print`/`minify`/`dom` surface of
// `cjson_core`. Scaffolded from porting-kit/harnesses/fuzz/fuzz_target.template.rs.
//
// The contract this enforces: the ported code must NEVER panic, abort, or
// exhibit UB on arbitrary bytes. That is the memory-safety guarantee the C
// original couldn't make. A crash here is a release blocker (PLAYBOOK Phase 4,
// gate 3). Overflow checks are on in fuzz builds, so a silent wraparound is a
// crash here too.
//
// No round-trip assertion: cJSON's own printer is not a right inverse of its
// parser (a DBL_MAX prints lossily, a NUL escape truncates the printed string
// — `oracle/corpus/dbl-max-reparse-null`, `nul-escape-truncates-print`), so
// "print then re-parse gives the same tree" would fail on faithful behaviour.
// What the port must agree with the C ON is the differential's job; this
// target only asks that nothing crashes.
#![no_main]

use cjson_core::{
    dom, minify, parse_with_length, parse_with_length_opts, parse_with_opts, print_buffered,
    print_preallocated, print_value,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = minify(data);
    // The three entry points that see different BUFFERS for the same bytes:
    // exact length, length with the NUL test, and the C string (strlen + 1).
    let _ = parse_with_length_opts(data, true);
    let _ = parse_with_opts(data, false);
    let _ = parse_with_opts(data, true);
    let Ok((value, _)) = parse_with_length(data) else {
        return;
    };
    // Sizes derived from the input, so the fuzzer steers them: the
    // preallocated printer's `ensure` accounting is a success predicate over
    // the buffer length, and its boundary is where an off-by-one would live.
    let len = usize::from(data.first().copied().unwrap_or(0));
    let prebuffer = i32::from(data.last().copied().unwrap_or(0)) - 64;
    for formatted in [false, true] {
        let _ = print_value(&value, formatted);
        let _ = print_buffered(&value, prebuffer, formatted);
        let mut buf = vec![0u8; len];
        let _ = print_preallocated(&value, &mut buf, formatted);
    }
    let dup = dom::duplicate(&value);
    let _ = dom::compare(&value, &dup, true);
    let _ = dom::compare(&value, &dup, false);
});
