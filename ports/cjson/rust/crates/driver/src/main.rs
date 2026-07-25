//! Rust differential driver — implements the SAME contract as
//! `../../oracle/driver.c`, so `diff_run.py` can diff the two byte-for-byte:
//!
//!   rjson_driver <mode>            # JSON bytes on stdin
//!     print / print-unformatted / roundtrip / minify
//!
//!   success        → canonical result on stdout, exit 0
//!   parse failure  → NOTHING on stdout, "parse error at offset N" on stderr
//!                    (stderr is off the compared contract), exit 1
//!   usage / not-yet-ported mode → exit 2, nothing on stdout
//!
//! `minify` is module 7 and not yet ported: it exits 2 (distinct from both
//! success and parse-failure, so a mistakenly-included minify vector would
//! DIVERGE loudly instead of silently passing).

use std::io::{Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = match std::env::args().nth(1) {
        Some(m) => m,
        None => {
            eprintln!("usage: rjson_driver <print|print-unformatted|roundtrip|minify>");
            return ExitCode::from(2);
        }
    };

    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        eprintln!("error reading stdin");
        return ExitCode::from(2);
    }

    let formatted = match mode.as_str() {
        "print" => true,
        "print-unformatted" | "roundtrip" => false,
        "minify" => {
            eprintln!("minify: not yet ported (module 7)");
            return ExitCode::from(2);
        }
        other => {
            eprintln!("unknown mode: {other}");
            return ExitCode::from(2);
        }
    };

    match cjson_core::parse_with_length(&input) {
        Err(e) => {
            eprintln!("parse error at offset {}", e.position);
            ExitCode::from(1)
        }
        Ok((value, _consumed)) => match cjson_core::print_value(&value, formatted) {
            Some(out) => {
                // fputs semantics: the exact bytes, no trailing newline
                if std::io::stdout().write_all(&out).is_err() {
                    return ExitCode::from(2);
                }
                ExitCode::SUCCESS
            }
            None => {
                eprintln!("print failed (module not yet ported)");
                ExitCode::from(2)
            }
        },
    }
}
