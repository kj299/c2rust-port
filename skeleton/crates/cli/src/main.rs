//! `cli` — thin entry point: parse args, read input, call `core`, render. Keep
//! logic OUT of here (it belongs in `core`, where it is testable and unsafe-free).
//! This binary is deliberately shaped to answer the example differential matrix
//! (`--help`, `--version`, `--format`, stdin), so `diff_run.py` can run against
//! it out of the box.

use std::io::Read;

/// RFC 8259 JSON string escaping. `{:?}` is NOT valid JSON: Rust debug-escapes
/// control characters as `\u{1}`, which JSON parsers reject (a `\u0001` escape is
/// required). "Rust emits strict JSON where C emitted raw bytes" is the
/// DIVERGENCES.md example of a behavioral improvement — the template has to
/// actually deliver it.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help") {
        println!("usage: port [--format text|json] [--version]  (reads key=value lines on stdin)");
        return;
    }
    if args.iter().any(|a| a == "--version") {
        println!("port {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let json = matches!(args.iter().position(|a| a == "--format"), Some(i) if args.get(i + 1).map(String::as_str) == Some("json"));

    let mut input = String::new();
    // A failed read (e.g. non-UTF-8 bytes on stdin) must not silently become
    // "empty input, exit 0" — exit-code fidelity is part of the differential
    // contract (LESSONS #4), and hostile stdin is exactly the input class the
    // port must handle *better* than the C.
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("read error: {e}");
        std::process::exit(1);
    }

    match core::parse(&input) {
        Ok(records) if json => {
            println!("[");
            for (i, r) in records.iter().enumerate() {
                let comma = if i + 1 < records.len() { "," } else { "" };
                println!(
                    "  {{\"key\": \"{}\", \"value\": \"{}\"}}{}",
                    json_escape(&r.key),
                    json_escape(&r.value),
                    comma
                );
            }
            println!("]");
        }
        Ok(records) => {
            for r in &records {
                println!("{}\t{}", r.key, r.value);
            }
        }
        Err(e) => {
            eprintln!("parse error: {e:?}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::json_escape;

    #[test]
    fn json_escape_is_rfc8259() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("q\"b\\"), "q\\\"b\\\\");
        assert_eq!(json_escape("tab\there"), "tab\\there");
        // The case {:?} got wrong: \u{1} is Rust, \u0001 is JSON.
        assert_eq!(json_escape("ctrl\u{1}byte"), "ctrl\\u0001byte");
        assert_eq!(json_escape("café"), "café"); // non-ASCII passes through raw
    }
}
