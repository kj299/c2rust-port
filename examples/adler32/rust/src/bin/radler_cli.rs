//! Thin CLI mirror of `../c/adler_cli.c`: read all of stdin, print the Adler-32
//! as 8 lowercase hex digits. Exits hard after output (the kit's liveness
//! pattern — never let a stray worker hold the process open).
use std::io::Read;

fn main() {
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_err() {
        std::process::exit(2);
    }
    println!("{:08x}", radler::adler32_bytes(&buf));
    std::process::exit(0);
}
