//! Rust differential driver — implements the SAME contract as
//! `../../oracle/driver.c`, so `diff_run.py` can diff the two byte-for-byte:
//!
//!   rjson_driver <mode>            # bytes on stdin
//!     print / print-unformatted / roundtrip / minify
//!     dup       parse → cJSON_Duplicate → print-unformatted  (exercises the
//!               DOM tree model + Duplicate; output must equal a plain
//!               round-trip, so the oracle's golden already validates it)
//!     dup-eq    parse → duplicate → cJSON_Compare(orig, dup, cs=true) →
//!               "true"/"false"  (the invariant differential for Compare +
//!               Duplicate: a value always compares equal to its clone)
//!     build     stdin is a VARIANT NAME: construct a document with the
//!               Create/Add builder API and print it (the builder surface's
//!               observable result)
//!     query     stdin is "<key>\n<json>": look the key up and describe it via
//!               the Is* predicates and the struct fields a C caller reads
//!               directly (type / valueint / valuestring)
//!
//!   success        → canonical result on stdout, exit 0
//!   parse failure  → NOTHING on stdout, a diagnostic on stderr (stderr is off
//!                    the compared contract), exit 1
//!   usage / unknown mode → exit 2, nothing on stdout
//!
//! The mode logic itself lives in `cjson_core::modes`, NOT here: the probe-test
//! glue needs the identical contract, and a contract implemented twice is a
//! contract that drifts (see that module's header).

use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(mode) = std::env::args().nth(1) else {
        eprintln!(
            "usage: rjson_driver \
             <print|print-unformatted|roundtrip|minify|dup|dup-eq|build|query>"
        );
        return ExitCode::from(2);
    };

    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        eprintln!("error reading stdin");
        return ExitCode::from(2);
    }

    let (rc, stdout) = cjson_core::modes::run(&mode, &input);
    if rc != 0 {
        // Diagnostics only — never on stdout, which is the compared surface.
        eprintln!("mode `{mode}` failed with code {rc}");
        return ExitCode::from(u8::try_from(rc).unwrap_or(2));
    }
    if std::io::stdout().write_all(&stdout).is_err() {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
