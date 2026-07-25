//! Rust differential driver — implements the SAME contract as
//! `../../oracle/driver.c`, so `diff_run.py` can diff the two byte-for-byte:
//!
//!   rjson_driver <mode>            # JSON bytes on stdin
//!     print / print-unformatted / roundtrip / minify
//!     dup       parse → cJSON_Duplicate → print-unformatted  (exercises the
//!               DOM tree model + Duplicate; output must equal a plain
//!               round-trip, so the oracle's golden already validates it)
//!     dup-eq    parse → duplicate → cJSON_Compare(orig, dup, cs=true) →
//!               "true"/"false"  (the invariant differential for Compare +
//!               Duplicate: a value always compares equal to its clone)
//!
//!   success        → canonical result on stdout, exit 0
//!   parse failure  → NOTHING on stdout, "parse error at offset N" on stderr
//!                    (stderr is off the compared contract), exit 1
//!   usage / unknown mode → exit 2, nothing on stdout

use std::io::{Read, Write};
use std::process::ExitCode;

fn emit(bytes: &[u8]) -> ExitCode {
    if std::io::stdout().write_all(bytes).is_err() {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let mode = match std::env::args().nth(1) {
        Some(m) => m,
        None => {
            eprintln!("usage: rjson_driver <print|print-unformatted|roundtrip|minify|dup|dup-eq>");
            return ExitCode::from(2);
        }
    };

    let mut input = Vec::new();
    if std::io::stdin().read_to_end(&mut input).is_err() {
        eprintln!("error reading stdin");
        return ExitCode::from(2);
    }

    // minify parses nothing; handle it before the parse path.
    if mode == "minify" {
        return emit(&cjson_core::minify(&input));
    }

    let formatted = match mode.as_str() {
        "print" => true,
        "print-unformatted" | "roundtrip" | "dup" | "dup-eq" => false,
        other => {
            eprintln!("unknown mode: {other}");
            return ExitCode::from(2);
        }
    };

    let value = match cjson_core::parse_with_length(&input) {
        Err(e) => {
            eprintln!("parse error at offset {}", e.position);
            return ExitCode::from(1);
        }
        Ok((value, _consumed)) => value,
    };

    match mode.as_str() {
        // DOM module: duplicate then print — output must match a plain round-trip
        "dup" => {
            let dup = cjson_core::dom::duplicate(&value);
            match cjson_core::print_value(&dup, false) {
                Some(out) => emit(&out),
                None => ExitCode::from(2),
            }
        }
        // DOM invariant: a value compares equal to its duplicate
        "dup-eq" => {
            let dup = cjson_core::dom::duplicate(&value);
            let eq = cjson_core::dom::compare(&value, &dup, true);
            emit(if eq { b"true" } else { b"false" })
        }
        _ => match cjson_core::print_value(&value, formatted) {
            Some(out) => emit(&out),
            None => {
                eprintln!("print failed (module not yet ported)");
                ExitCode::from(2)
            }
        },
    }
}
