//! Modules 4/5, print side: `print_value` / `print_array` / `print_object` and
//! the printbuffer state, ported from cJSON.c:1380–1452 (value dispatch),
//! 1552–1611 (array), 1732–1845 (object).
//!
//! The C's `printbuffer` (`ensure`/`update_offset`, cJSON.c:447–544) exists to
//! grow a manual byte buffer safely — its integer-overflow guard (2683d4d) and
//! offset double-check are exactly what `Vec` growth provides intrinsically, so
//! module 4's print half reduces to `Vec<u8>` plus the two fields the format
//! actually observes: `format` and `depth`.
//!
//! Formatted layout, probed against the oracle (2026-07-25):
//!   * arrays are INLINE: `[1, 2, 3]` — comma-space separators, no newlines;
//!   * objects break lines: `{\n` + depth×`\t` + key + `:\t` + value + `,`? +
//!     `\n` per entry, closing brace at (depth−1)×`\t`;
//!   * BOTH array and object printing increment `depth`, so an object nested
//!     inside an array indents by the combined depth (`[1, {\n\t\t"a":…`);
//!   * an empty object formats as `{\n}` (loop never runs, close at depth−1).

use crate::num::print_number;
use crate::string::print_string;
use crate::value::Value;

struct Printer {
    out: Vec<u8>,
    format: bool,
    depth: usize,
}

impl Printer {
    /// cJSON.c:1380 `print_value` dispatch.
    fn value(&mut self, v: &Value) -> Option<()> {
        match v {
            Value::Null => self.out.extend_from_slice(b"null"),
            Value::False => self.out.extend_from_slice(b"false"),
            Value::True => self.out.extend_from_slice(b"true"),
            Value::Number(n) => self.out.extend_from_slice(print_number(n).as_bytes()),
            Value::String(s) => self.out.extend_from_slice(&print_string(s)),
            // cJSON_Raw with a NULL valuestring fails in C; a parse can never
            // produce Raw (DOM-only, module 6), so the driver can't reach this.
            Value::Raw(_) => return None,
            Value::Array(items) => self.array(items)?,
            Value::Object(entries) => self.object(entries)?,
        }
        Some(())
    }

    /// cJSON.c:1552 `print_array` — inline, `", "` when formatted.
    fn array(&mut self, items: &[Value]) -> Option<()> {
        self.out.push(b'[');
        self.depth = self.depth.saturating_add(1);
        let mut first = true;
        for item in items {
            if !first {
                self.out.push(b',');
                if self.format {
                    self.out.push(b' ');
                }
            }
            first = false;
            self.value(item)?;
        }
        self.out.push(b']');
        self.depth = self.depth.saturating_sub(1);
        Some(())
    }

    /// cJSON.c:1732 `print_object` — line-per-entry when formatted; keys go
    /// through `print_string` (same NUL-truncation as values, probed:
    /// a NUL-escaped key prints truncated).
    fn object(&mut self, entries: &[(Vec<u8>, Value)]) -> Option<()> {
        self.out.push(b'{');
        self.depth = self.depth.saturating_add(1);
        if self.format {
            self.out.push(b'\n');
        }
        let mut it = entries.iter().peekable();
        while let Some((key, value)) = it.next() {
            if self.format {
                for _ in 0..self.depth {
                    self.out.push(b'\t');
                }
            }
            self.out.extend_from_slice(&print_string(key));
            self.out.push(b':');
            if self.format {
                self.out.push(b'\t');
            }
            self.value(value)?;
            if it.peek().is_some() {
                self.out.push(b',');
            }
            if self.format {
                self.out.push(b'\n');
            }
        }
        if self.format {
            for _ in 0..self.depth.saturating_sub(1) {
                self.out.push(b'\t');
            }
        }
        self.out.push(b'}');
        self.depth = self.depth.saturating_sub(1);
        Some(())
    }
}

/// Render a value. Returns None only for the not-yet-ported `Raw` arm (module
/// 6, unreachable from parse) — the driver maps that to its "print failed"
/// exit.
#[must_use]
pub fn print_value(value: &Value, formatted: bool) -> Option<Vec<u8>> {
    let mut p = Printer {
        out: Vec::new(),
        format: formatted,
        depth: 0,
    };
    p.value(value)?;
    Some(p.out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Number;

    fn n(d: f64) -> Value {
        #[allow(clippy::cast_possible_truncation)] // test values are small ints
        Value::Number(Number { d, i: d as i32 })
    }

    #[test]
    fn scalar_bytes_match_c() {
        assert_eq!(print_value(&Value::Null, false).unwrap(), b"null");
        assert_eq!(print_value(&Value::True, false).unwrap(), b"true");
        assert_eq!(
            print_value(&Value::String(b"hi".to_vec()), false).unwrap(),
            b"\"hi\""
        );
    }

    // Formatted layouts below are the OBSERVED oracle outputs (probed).
    #[test]
    fn array_layout_matches_c() {
        let v = Value::Array(vec![n(1.0), n(2.0), n(3.0)]);
        assert_eq!(print_value(&v, false).unwrap(), b"[1,2,3]");
        assert_eq!(print_value(&v, true).unwrap(), b"[1, 2, 3]");
        assert_eq!(print_value(&Value::Array(vec![]), true).unwrap(), b"[]");
    }

    #[test]
    fn object_layout_matches_c() {
        let v = Value::Object(vec![(b"a".to_vec(), n(1.0)), (b"b".to_vec(), n(2.0))]);
        assert_eq!(print_value(&v, false).unwrap(), b"{\"a\":1,\"b\":2}");
        assert_eq!(
            print_value(&v, true).unwrap(),
            b"{\n\t\"a\":\t1,\n\t\"b\":\t2\n}"
        );
        // empty object formats as {\n}
        assert_eq!(print_value(&Value::Object(vec![]), true).unwrap(), b"{\n}");
    }

    #[test]
    fn nested_depth_indent_matches_c() {
        // probed: [1,{"a":1}] formatted → [1, {\n\t\t"a":\t1\n\t}]
        let v = Value::Array(vec![n(1.0), Value::Object(vec![(b"a".to_vec(), n(1.0))])]);
        assert_eq!(
            print_value(&v, true).unwrap(),
            b"[1, {\n\t\t\"a\":\t1\n\t}]"
        );
        // probed: {"a":{}} formatted → {\n\t"a":\t{\n\t}\n}
        let v = Value::Object(vec![(b"a".to_vec(), Value::Object(vec![]))]);
        assert_eq!(print_value(&v, true).unwrap(), b"{\n\t\"a\":\t{\n\t}\n}");
    }
}
