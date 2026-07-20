//! cando-style function-level differential driver — RUST side. Same protocol as
//! `../../c/adler_drv.c`: `driver <func> [args...]` → canonical stdout, exit
//! 0/nonzero. No `unwrap()` on harness-fed argv — return a nonzero exit so a bad
//! vector is a clean baseline failure, not a panic.
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(func) = args.first().map(String::as_str) else {
        eprintln!("usage: driver <func> [args...]");
        exit(2);
    };
    match func {
        "adler32" => match args.get(1) {
            Some(data) => println!("{:08x}", radler::adler32_bytes(data.as_bytes())),
            None => exit(3),
        },
        other => {
            eprintln!("unsupported function: {other}");
            exit(4);
        }
    }
}
