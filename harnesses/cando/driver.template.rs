//! cando-style function-level differential driver — RUST side.
//!
//! Build this against the Rust port; it is the same protocol as
//! driver.template.c (the C oracle side). The harness (cando_diff.py) runs both
//! over a vector suite and diffs, testing each ported function individually.
//!
//! Protocol:
//!   argv[1] = function name, argv[2..] = string args, optional stdin.
//!   Print the result CANONICALLY to stdout — byte-identical format to the C
//!   driver (same radix, separators, trailing newline). Exit 0 on success,
//!   nonzero on error / unsupported function.
//!
//! Keep the driver THIN: parse args, call ONE library function, serialize the
//! result. The logic under test lives in the crate, not here. No `unwrap()` on
//! the argv/stdin the harness feeds you — return a nonzero exit instead, so a
//! bad vector is a clean baseline failure, not a panic.

use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(func) = args.first().map(String::as_str) else {
        eprintln!("usage: driver <func> [args...]");
        exit(2);
    };

    match func {
        // One arm per exported function under test. Replace with the real calls.
        "__EXAMPLE__checksum" => {
            // let r = yourcrate::checksum(args[1].as_bytes());
            // println!("{r}");
        }
        "__EXAMPLE__parse" => {
            // match yourcrate::parse(&args[1]) {
            //     Ok(v) => println!("{v}"),
            //     Err(_) => exit(1),
            // }
        }
        other => {
            eprintln!("unsupported function: {other}");
            exit(4);
        }
    }
}
