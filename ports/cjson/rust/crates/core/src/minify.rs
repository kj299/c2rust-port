//! Module 7 (entry-minify): `cJSON_Minify`, ported from cJSON.c:2812–2910.
//! This is the #338 site — in C, `minify_string` walked raw `char*` pointers
//! in place and both read and wrote out of bounds on a malformed string; the
//! v1.7.18 code is the fixed version, and the Rust port makes the bound
//! structural (slice indices, no raw pointer walk).
//!
//! Quirks probed against the oracle (2026-07-25), replicated on purpose:
//!   * strings are copied VERBATIM — inner whitespace and comment-looking
//!     content (`"a // b /* c */ d"`) are preserved;
//!   * a `\"` inside a string does not end it;
//!   * an unterminated string / block comment / line comment consumes to EOF
//!     (yielding whatever was copied so far — for a bare `/* …` that is nothing);
//!   * a LONE `/` (not `//` or `/*`) is DROPPED, not copied: `1/2` → `12`
//!     (a C quirk — arguably a bug, but faithful behavior).

/// cJSON.c:2861 `cJSON_Minify`. Operates on bytes; returns the minified bytes.
/// (The C mutates a NUL-terminated buffer in place and stops at the NUL; the
/// driver reads the exact stdin length, and a real interior NUL simply ends
/// the C's walk — replicated by stopping at the first NUL.)
#[must_use]
pub fn minify(input: &[u8]) -> Vec<u8> {
    // C walks a NUL-terminated C string: an interior NUL ends minification.
    let end = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    let json = &input[..end];

    let mut out = Vec::with_capacity(json.len());
    let mut i = 0;
    while i < json.len() {
        match json[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i = i.saturating_add(1),
            b'/' => {
                if json.get(i.saturating_add(1)) == Some(&b'/') {
                    // line comment: skip through the newline (inclusive)
                    i = i.saturating_add(2);
                    while i < json.len() && json[i] != b'\n' {
                        i = i.saturating_add(1);
                    }
                    if i < json.len() {
                        i = i.saturating_add(1); // consume the '\n'
                    }
                } else if json.get(i.saturating_add(1)) == Some(&b'*') {
                    // block comment: skip through the closing "*/" (inclusive)
                    i = i.saturating_add(2);
                    while i < json.len()
                        && !(json[i] == b'*' && json.get(i.saturating_add(1)) == Some(&b'/'))
                    {
                        i = i.saturating_add(1);
                    }
                    if i < json.len() {
                        i = i.saturating_add(2); // consume "*/"
                    }
                } else {
                    // lone '/': the C's `else { json++; }` drops it (quirk)
                    i = i.saturating_add(1);
                }
            }
            b'"' => {
                // Faithful port of the C's `minify_string` (cJSON.c:2839), which
                // does NOT track escape parity: it copies bytes, and ONLY when a
                // byte is `\` *immediately followed by* `"` does it copy the `"`
                // too and keep going. So `\\` is copied as two ordinary bytes,
                // and the fuzzer-found `"\\" "` input hinges on this — the second
                // `\` sees a `"` next and escapes it even though the backslash is
                // itself escaped. Replicated exactly (a lone `"` closes; an
                // unterminated string copies to EOF).
                out.push(b'"');
                i = i.saturating_add(1);
                while i < json.len() {
                    let b = json[i];
                    if b == b'"' {
                        out.push(b'"');
                        i = i.saturating_add(1);
                        break; // closing quote
                    }
                    if b == b'\\' && json.get(i.saturating_add(1)) == Some(&b'"') {
                        out.push(b'\\');
                        out.push(b'"'); // escaped quote: copy both, string continues
                        i = i.saturating_add(2);
                        continue;
                    }
                    out.push(b);
                    i = i.saturating_add(1);
                }
            }
            other => {
                out.push(other);
                i = i.saturating_add(1);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expectations are OBSERVED oracle output (probed).
    #[test]
    fn minify_matches_c() {
        assert_eq!(
            minify(b"{ \"a\" : 1 ,  \"b\" : [ 2 , 3 ] }"),
            b"{\"a\":1,\"b\":[2,3]}"
        );
        assert_eq!(minify(b"{\"a\":1} // tail"), b"{\"a\":1}");
        assert_eq!(minify(b"/* x */ {\"a\":1}"), b"{\"a\":1}");
        assert_eq!(minify(b"/* never closed"), b""); // unterminated block → nothing
        assert_eq!(minify(b"// abc"), b""); // unterminated line → nothing
        assert_eq!(minify(b""), b"");
        assert_eq!(minify(b"   \t\n "), b"");
    }

    #[test]
    fn strings_preserved_verbatim() {
        assert_eq!(minify(b"{ \"a b\" : \"c d\" }"), b"{\"a b\":\"c d\"}");
        // comment-looking content inside a string is untouched
        assert_eq!(
            minify(b"{\"k\":\"a // b /* c */ d\"}"),
            b"{\"k\":\"a // b /* c */ d\"}"
        );
        // an escaped quote does not end the string
        assert_eq!(minify(br#"{"a":"x\"y"}"#), br#"{"a":"x\"y"}"#);
    }

    #[test]
    fn quirks_match_c() {
        // lone '/' is DROPPED (the C quirk): 1/2 → 12
        assert_eq!(minify(b"{\"a\":1/2}"), b"{\"a\":12}");
        // comments interleaved in an array
        assert_eq!(minify(b"[ 1, /* c */ 2, // d\n 3 ]"), b"[1,2,3]");
    }

    #[test]
    fn escape_parity_quirk_found_by_fuzz() {
        // diff-fuzz finding (2026-07-25): the C's minify_string does NOT track
        // escape parity — a `\` before a `"` escapes that quote even when the
        // backslash is itself part of a `\\`. So `"\\" "` keeps the space:
        // the second `\` sees the `"` and treats the pair as an escaped quote,
        // the string does not close there. An escape-tracking port dropped the
        // space; this pins the C's actual bytes.
        assert_eq!(minify(b"\"\\\\\" \""), b"\"\\\\\" \"");
        assert_eq!(minify(b"\"\\\\\"\r\\"), b"\"\\\\\"\r\\");
    }
}
