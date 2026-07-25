//! Probe glue — the ONE hand-written piece of the probe-then-port pipeline
//! (harnesses/probe/probe.py, LESSONS #21). Maps a probe's driver-mode args to
//! the core API with the SAME (exit code, stdout) contract as
//! `crates/driver/src/main.rs`, so the generated `probes_quirks.rs`
//! expectations — the C oracle's observed bytes — apply verbatim.
//!
//! Keep this in lockstep with the driver's dispatch: a drift here would make
//! the probe tests measure something the differential doesn't.

pub fn run_probe(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
    let mode = *args.first().expect("probe args carry the driver mode");

    // minify parses nothing; handle it before the parse path (as the driver does)
    if mode == "minify" {
        return (0, cjson_core::minify(stdin));
    }

    let formatted = match mode {
        "print" => true,
        "print-unformatted" | "roundtrip" | "dup" | "dup-eq" => false,
        other => panic!("probe_glue: unknown driver mode `{other}`"),
    };

    let value = match cjson_core::parse_with_length(stdin) {
        Err(_) => return (1, Vec::new()), // parse failure: rc 1, nothing on stdout
        Ok((value, _consumed)) => value,
    };

    match mode {
        "dup" => match cjson_core::print_value(&cjson_core::dom::duplicate(&value), false) {
            Some(out) => (0, out),
            None => (2, Vec::new()),
        },
        "dup-eq" => {
            let dup = cjson_core::dom::duplicate(&value);
            let eq = cjson_core::dom::compare(&value, &dup, true);
            let verdict: &[u8] = if eq { b"true" } else { b"false" };
            (0, verdict.to_vec())
        }
        _ => match cjson_core::print_value(&value, formatted) {
            Some(out) => (0, out),
            None => (2, Vec::new()),
        },
    }
}
