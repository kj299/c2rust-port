//! The print-side arms of `print_value` (cJSON.c:1380–1452). Formatted vs
//! unformatted output differs only inside arrays/objects (indentation and
//! newlines); scalars and strings print identically in both modes, so
//! `formatted` is accepted-and-unused until the recursive-core module lands.
//!
//! Output is BYTES: string values may legally contain non-UTF-8 (see
//! `value::Value::String`), so a Rust `String` cannot carry the result.

use crate::num::print_number;
use crate::string::print_string;
use crate::value::Value;

/// Render a value. Returns None for the not-yet-ported tree/raw arms — the
/// driver maps that to its "print failed" exit, which no C-accepted input in
/// the increment's matrix can trigger.
#[must_use]
pub fn print_value(value: &Value, _formatted: bool) -> Option<Vec<u8>> {
    match value {
        Value::Null => Some(b"null".to_vec()),
        Value::False => Some(b"false".to_vec()),
        Value::True => Some(b"true".to_vec()),
        Value::Number(n) => Some(print_number(n).into_bytes()),
        Value::String(s) => Some(print_string(s)),
        // ⏳ modules 5/6: raw/array/object printing not yet ported
        Value::Raw(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Number;

    #[test]
    fn scalar_bytes_match_c() {
        assert_eq!(print_value(&Value::Null, false).unwrap(), b"null");
        assert_eq!(print_value(&Value::False, true).unwrap(), b"false");
        assert_eq!(print_value(&Value::True, false).unwrap(), b"true");
        assert_eq!(
            print_value(&Value::Number(Number { d: 42.0, i: 42 }), false).unwrap(),
            b"42"
        );
        assert_eq!(
            print_value(&Value::String(b"hi".to_vec()), false).unwrap(),
            b"\"hi\""
        );
    }
}
