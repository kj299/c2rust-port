//! The print-side scalar arms of `print_value` (cJSON.c:1380–1452). Formatted
//! vs unformatted output differs only inside arrays/objects (indentation and
//! newlines); a bare scalar prints identically in both modes, so `formatted`
//! is accepted-and-unused until the recursive-core module lands.

use crate::num::print_number;
use crate::value::Value;

/// Render a value. Returns None for the not-yet-ported tree/string arms —
/// the driver maps that to its "print failed" exit, which no C-accepted input
/// in the increment's matrix can trigger.
#[must_use]
pub fn print_value(value: &Value, _formatted: bool) -> Option<String> {
    match value {
        Value::Null => Some("null".to_string()),
        Value::False => Some("false".to_string()),
        Value::True => Some("true".to_string()),
        Value::Number(n) => Some(print_number(n)),
        // ⏳ modules 3/5/6: string/raw/array/object printing not yet ported
        Value::String(_) | Value::Raw(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Number;

    #[test]
    fn scalar_bytes_match_c() {
        assert_eq!(print_value(&Value::Null, false).unwrap(), "null");
        assert_eq!(print_value(&Value::False, true).unwrap(), "false");
        assert_eq!(print_value(&Value::True, false).unwrap(), "true");
        assert_eq!(
            print_value(&Value::Number(Number { d: 42.0, i: 42 }), false).unwrap(),
            "42"
        );
    }
}
