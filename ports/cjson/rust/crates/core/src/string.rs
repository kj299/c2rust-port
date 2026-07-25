//! Module 3 (string-parse): `parse_string` / `print_string_ptr` /
//! `parse_hex4` / `utf16_literal_to_utf8`, ported from cJSON.c:623–1037.
//! This is the a167d9e OOB-read territory — in C, every guard here was earned
//! by a fix; in Rust the reads are slice-bounds-checked, and the port's job is
//! byte-identical BEHAVIOR.
//!
//! C quirks replicated ON PURPOSE (each probed against the oracle, 2026-07-25;
//! a silent "fix" would be an unledgered divergence):
//!   * `parse_hex4` returns 0 for INVALID hex — indistinguishable from a real
//!     `\u0000`, so `"\uZZZZ"` parses as a NUL byte, not an error.
//!   * string content is copied VERBATIM — no UTF-8 validation; raw 0xFF (or a
//!     raw NUL) inside quotes is accepted and stored.
//!   * `print_string_ptr` walks a NUL-terminated C string, so printing stops
//!     at the first interior NUL: `"a\u0000b"` prints as `"a"`.
//!   * a lone/low/mismatched surrogate or a `\uXXX`-too-short-before-the-quote
//!     fails the parse (the real validation the C does perform).

use crate::parse::ParseBuffer;

/// cJSON.c:623 `parse_hex4` — returns 0 on invalid hex (the quirk above).
#[allow(clippy::arithmetic_side_effects)] // digit math on range-matched bytes
                                          // (b is inside the matched ASCII range, nibble <= 15, h <= 0xFFFF after 4
                                          // nibbles): none of it can wrap.
fn parse_hex4(input: &[u8; 4]) -> u32 {
    let mut h: u32 = 0;
    for (i, &b) in input.iter().enumerate() {
        let nibble = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'A'..=b'F' => u32::from(b - b'A') + 10,
            b'a'..=b'f' => u32::from(b - b'a') + 10,
            _ => return 0, // invalid → 0, same as the C
        };
        h += nibble;
        if i < 3 {
            h <<= 4;
        }
    }
    h
}

/// cJSON.c:659 `utf16_literal_to_utf8` — `input` starts at the `\` of `\uXXXX`
/// and ends at the closing quote (the C's `input_end`). On success returns
/// (consumed input bytes: 6 or 12, the UTF-8 encoding); None = fail.
fn utf16_literal_to_utf8(input: &[u8]) -> Option<(usize, Vec<u8>)> {
    if input.len() < 6 {
        return None; // input ends unexpectedly
    }
    let first_code = parse_hex4(input[2..6].try_into().expect("len checked"));

    // a LOW surrogate first is invalid
    if (0xDC00..=0xDFFF).contains(&first_code) {
        return None;
    }

    #[allow(clippy::arithmetic_side_effects)] // 0x10000 + (10-bit << 10 | 10-bit)
    // is at most 0x10FFFF: cannot overflow u32
    let (sequence_length, codepoint) = if (0xD800..=0xDBFF).contains(&first_code) {
        // surrogate pair: need a second \uXXXX in DC00..=DFFF
        if input.len() < 12 {
            return None;
        }
        if input[6] != b'\\' || input[7] != b'u' {
            return None;
        }
        let second_code = parse_hex4(input[8..12].try_into().expect("len checked"));
        if !(0xDC00..=0xDFFF).contains(&second_code) {
            return None;
        }
        (
            12usize,
            0x10000u32 + (((first_code & 0x3FF) << 10) | (second_code & 0x3FF)),
        )
    } else {
        (6usize, first_code)
    };

    // encode as UTF-8, exactly the C's byte math (cJSON.c:723–768)
    let mut cp = codepoint;
    let out = if cp < 0x80 {
        #[allow(clippy::cast_possible_truncation)] // cp < 0x80 fits a byte
        let b = (cp & 0x7F) as u8;
        vec![b]
    } else {
        let (len, first_byte_mark) = if cp < 0x800 {
            (2usize, 0xC0u8)
        } else if cp < 0x1_0000 {
            (3, 0xE0)
        } else {
            // from surrogate math, cp <= 0x10FFFF always holds here
            (4, 0xF0)
        };
        let mut buf = vec![0u8; len];
        for slot in buf.iter_mut().skip(1).rev() {
            #[allow(clippy::cast_possible_truncation)] // masked to 8 bits
            {
                *slot = ((cp | 0x80) & 0xBF) as u8;
            }
            cp >>= 6;
        }
        #[allow(clippy::cast_possible_truncation)] // masked to 8 bits
        {
            buf[0] = ((cp | u32::from(first_byte_mark)) & 0xFF) as u8;
        }
        buf
    };
    Some((sequence_length, out))
}

/// cJSON.c:781 `parse_string`. On entry the buffer points at the opening `"`.
/// Success: returns the unescaped bytes and sets the offset one past the
/// closing quote. Failure: sets the offset to the C's error position.
///
/// The error is deliberately unit: like the C's `cJSON_bool`, all failure
/// detail lives in the buffer offset the caller reads (`ParseError` is built
/// at the entry point, mirroring cJSON's single global error position).
#[allow(clippy::result_unit_err)]
pub fn parse_string(buf: &mut ParseBuffer) -> Result<Vec<u8>, ()> {
    let content = buf.content;
    let start = buf.offset;
    if content.get(start) != Some(&b'"') {
        return Err(());
    }

    // Pre-scan for the closing quote, skipping escaped pairs. The C's "last
    // input character is a backslash" guard (the a167d9e class) is the
    // `end + 1 >= len` check.
    let mut end = start.saturating_add(1);
    while end < content.len() && content[end] != b'"' {
        if content[end] == b'\\' {
            if end.saturating_add(1) >= content.len() {
                // trailing backslash: fail with the offset where we stood
                buf.offset = start.saturating_add(1);
                return Err(());
            }
            end = end.saturating_add(1); // skip the escaped char
        }
        end = end.saturating_add(1);
    }
    if end >= content.len() || content[end] != b'"' {
        buf.offset = start.saturating_add(1); // string ended unexpectedly
        return Err(());
    }

    // Unescape loop over input[start+1 .. end]
    let mut out: Vec<u8> = Vec::with_capacity(end.saturating_sub(start));
    let mut ip = start.saturating_add(1);
    while ip < end {
        let b = content[ip];
        if b != b'\\' {
            out.push(b); // verbatim — including raw NUL / invalid UTF-8
            ip = ip.saturating_add(1);
            continue;
        }
        // escape sequence: the pre-scan guarantees ip+1 < end or the escaped
        // char is the pre-quote byte; C indexes input_pointer[1] directly.
        let esc = content.get(ip.saturating_add(1)).copied();
        let mut sequence_length = 2usize;
        match esc {
            Some(b'b') => out.push(0x08),
            Some(b'f') => out.push(0x0C),
            Some(b'n') => out.push(b'\n'),
            Some(b'r') => out.push(b'\r'),
            Some(b't') => out.push(b'\t'),
            Some(b'"') | Some(b'\\') | Some(b'/') => {
                out.push(esc.expect("matched Some"));
            }
            Some(b'u') => match utf16_literal_to_utf8(&content[ip..end]) {
                Some((consumed, utf8)) => {
                    sequence_length = consumed;
                    out.extend_from_slice(&utf8);
                }
                None => {
                    buf.offset = ip; // C: offset = input_pointer position
                    return Err(());
                }
            },
            _ => {
                buf.offset = ip;
                return Err(());
            }
        }
        ip = ip.saturating_add(sequence_length);
    }

    buf.offset = end.saturating_add(1); // one past the closing quote
    Ok(out)
}

/// cJSON.c:911 `print_string_ptr`. `input` is the stored bytes; the C walks a
/// NUL-terminated `char*`, so the port truncates at the first interior NUL —
/// probed: `"a\u0000b"` prints as `"a"`.
pub fn print_string(input: &[u8]) -> Vec<u8> {
    let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    let s = &input[..end];

    let mut out = Vec::with_capacity(s.len().saturating_add(2));
    out.push(b'"');
    for &b in s {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            _ if b < 32 => {
                // C: sprintf "u%04x" — lowercase hex, 4 digits
                out.extend_from_slice(format!("\\u{:04x}", b).as_bytes());
            }
            _ => out.push(b), // includes bytes >= 0x80, copied raw
        }
    }
    out.push(b'"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ParseBuffer;

    fn parse(input: &[u8]) -> Result<Vec<u8>, ()> {
        let mut buf = ParseBuffer {
            content: input,
            offset: 0,
            depth: 0,
        };
        parse_string(&mut buf)
    }

    // Expectations below are OBSERVED oracle behavior (probed 2026-07-25).
    #[test]
    fn escapes_unescape_like_c() {
        assert_eq!(parse(br#""a\nb""#).unwrap(), b"a\nb");
        assert_eq!(
            parse(br#""\b\f\n\r\t\\\"\/""#).unwrap(),
            b"\x08\x0C\n\r\t\\\"/"
        );
        assert_eq!(parse(br#""\u0041""#).unwrap(), b"A");
    }

    #[test]
    fn surrogates_like_c() {
        // G-clef via escaped pair
        assert_eq!(parse(br#""\uD834\uDD1E""#).unwrap(), "𝄞".as_bytes());
        assert!(parse(br#""\uDC00""#).is_err()); // lone LOW surrogate
        assert!(parse(br#""\uD800""#).is_err()); // lone HIGH (no second seq)
        assert!(parse(br#""\uD800\u0041""#).is_err()); // bad second half
        assert!(parse(br#""\u041""#).is_err()); // too short before the quote
    }

    #[test]
    fn quirks_probed_against_oracle() {
        // invalid hex → NUL, not an error (parse_hex4-returns-0 quirk)
        assert_eq!(parse(br#""a\uZZZZb""#).unwrap(), b"a\0b");
        // \u0000 parses; printing then truncates at the NUL
        assert_eq!(parse(br#""a\u0000b""#).unwrap(), b"a\0b");
        assert_eq!(print_string(b"a\0b"), b"\"a\"");
        // raw non-UTF-8 byte is stored and printed verbatim
        assert_eq!(parse(b"\"a\xFFb\"").unwrap(), b"a\xFFb");
        assert_eq!(print_string(b"a\xFFb"), b"\"a\xFFb\"");
    }

    #[test]
    fn rejects_like_c() {
        assert!(parse(br#""abc"#).is_err()); // unterminated
        assert!(parse(br#""abc\"#).is_err()); // trailing backslash (a167d9e guard)
        assert!(parse(br#""\x41""#).is_err()); // unknown escape
    }

    #[test]
    fn print_escapes_like_c() {
        assert_eq!(print_string(b""), b"\"\"");
        assert_eq!(print_string(b"a\nb"), b"\"a\\nb\"");
        assert_eq!(print_string(b"\x01"), b"\"\\u0001\"");
        assert_eq!(print_string(b"q\"w\\e"), b"\"q\\\"w\\\\e\"");
        // '/' is NOT re-escaped on output (probed: "\/" prints as "/")
        assert_eq!(print_string(b"a/b"), b"\"a/b\"");
    }

    #[test]
    fn offset_lands_after_closing_quote() {
        let input: &[u8] = br#""hi" tail"#;
        let mut buf = ParseBuffer {
            content: input,
            offset: 0,
            depth: 0,
        };
        parse_string(&mut buf).unwrap();
        assert_eq!(buf.offset, 4);
    }
}
