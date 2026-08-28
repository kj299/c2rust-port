//! The differential driver's mode dispatch, as library code.
//!
//! `oracle/driver.c` defines a byte-for-byte contract (mode + stdin → stdout +
//! exit code) that the Rust side must match. That contract was implemented
//! TWICE on the Rust side — once in `crates/driver` (what `diff_run` executes)
//! and once in the probe-test glue (what the generated `probes_*.rs` tests
//! call) — so the two could drift and the tests would then be measuring
//! something the differential does not.
//!
//! The kit's own principle is that fidelity lives in exactly one place
//! (`RETROSPECTIVE-kit-v1.md` §2, "shared fidelity as architecture": extracting
//! `compare_one` meant four gates share one verdict). This module is that place
//! for the port: `crates/driver` and `tests/probe_glue` are both thin wrappers
//! over `run`, so a change to the contract cannot reach one and miss the other.
//!
//! Returns `(exit_code, stdout_bytes)`; stderr is deliberately not modelled —
//! `diff_run` keeps it off the compared contract (error *text* is a documented
//! divergence), so the caller prints whatever diagnostic it likes.

use crate::dom;
use crate::value::Value;

/// Exit code for a usage error / unrepresentable result, matching the C driver.
const RC_USAGE: i32 = 2;
/// Exit code for a parse failure, matching the C driver.
const RC_PARSE: i32 = 1;

/// Build one of the named documents with the DOM builder API. `None` for an
/// unknown variant (the C driver exits 2 on that).
#[must_use]
pub fn build_variant(variant: &str) -> Option<Value> {
    let mut root;
    match variant {
        "flat" => {
            root = Value::Object(Vec::new());
            dom::add_string_to_object(&mut root, b"s", b"hi");
            dom::add_number_to_object(&mut root, b"n", 42.0);
            dom::add_bool_to_object(&mut root, b"t", true);
            dom::add_bool_to_object(&mut root, b"f", false);
            dom::add_null_to_object(&mut root, b"z");
        }
        "array" => {
            root = Value::Array(Vec::new());
            dom::add_item_to_array(&mut root, dom::number(1.0));
            dom::add_item_to_array(&mut root, Value::String(b"two".to_vec()));
            dom::add_item_to_array(&mut root, Value::True);
            dom::add_item_to_array(&mut root, Value::Null);
        }
        "nested" => {
            root = Value::Object(Vec::new());
            let mut arr = Value::Array(Vec::new());
            let mut inner = Value::Object(Vec::new());
            dom::add_number_to_object(&mut inner, b"deep", -1.0);
            dom::add_item_to_array(&mut arr, inner);
            dom::add_item_to_object(&mut root, b"arr", arr);
        }
        "numbers" => {
            root = Value::Array(Vec::new());
            for d in [0.0, -1.0, 0.1, 1e308, f64::INFINITY] {
                dom::add_item_to_array(&mut root, dom::number(d));
            }
        }
        // Probed: adding the SAME key twice APPENDS, it does not replace.
        "dupkey" => {
            root = Value::Object(Vec::new());
            dom::add_number_to_object(&mut root, b"k", 1.0);
            dom::add_number_to_object(&mut root, b"k", 2.0);
        }
        // Probed: `cJSON_AddItemToObject(obj, key, NULL)` is SILENTLY IGNORED —
        // no error, no crash, the key just never appears. Rust has no null
        // `Value`, so the absence is modelled directly by not adding it, which
        // reproduces the C's observable output exactly.
        "add-null" => {
            root = Value::Object(Vec::new());
            dom::add_number_to_object(&mut root, b"b", 1.0);
        }
        "empty" => root = Value::Object(Vec::new()),
        "strings" => {
            root = Value::Array(Vec::new());
            for s in [&b""[..], &b"a\"b\\c"[..], &b"tab\there"[..]] {
                dom::add_item_to_array(&mut root, Value::String(s.to_vec()));
            }
        }
        _ => return None,
    }
    Some(root)
}

/// `query`: stdin is `<key>\n<json>`. Emits the C driver's fixed-order
/// description, built from the `Is*` predicates and the struct-field views
/// (`type` / `valueint` / `valuestring`) that a C caller reads straight off the
/// pointer.
fn query(input: &[u8]) -> (i32, Vec<u8>) {
    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
        return (RC_USAGE, Vec::new());
    };
    // `split_at` + `get(1..)` rather than `input[nl + 1..]`: the workspace denies
    // arithmetic_side_effects on indices derived from input, and skipping the
    // delimiter without arithmetic keeps it that way.
    let (key, rest) = input.split_at(nl);
    let json = rest.get(1..).unwrap_or(&[]);
    let Ok((value, _)) = crate::parse_with_length(json) else {
        return (RC_PARSE, Vec::new());
    };
    let Some(got) = dom::get_object_item(&value, key, true) else {
        return (0, b"missing".to_vec());
    };
    let mut out = b"is=".to_vec();
    for (flag, on) in [
        (b'I', dom::is_invalid(got)),
        (b'N', dom::is_null(got)),
        (b'F', dom::is_false(got)),
        (b'T', dom::is_true(got)),
        (b'B', dom::is_bool(got)),
        (b'M', dom::is_number(got)),
        (b'S', dom::is_string(got)),
        (b'R', dom::is_raw(got)),
        (b'A', dom::is_array(got)),
        (b'O', dom::is_object(got)),
    ] {
        if on {
            out.push(flag);
        }
    }
    out.extend_from_slice(
        format!(
            ";type={};int={};str=",
            dom::type_code(got),
            dom::value_int(got)
        )
        .as_bytes(),
    );
    match dom::value_string(got) {
        // `valuestring` is a C string and the driver prints it with `%s`, which
        // stops at the first NUL — so a string with an interior NUL truncates.
        Some(s) => out.extend_from_slice(&s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())]),
        None => out.push(b'-'),
    }
    out.extend_from_slice(format!(";size={};print=", dom::get_array_size(got)).as_bytes());
    match crate::print_value(got, false) {
        Some(p) => out.extend_from_slice(&p),
        None => return (RC_USAGE, Vec::new()),
    }
    (0, out)
}

/// Run one driver mode. `(exit_code, stdout)`.
#[must_use]
pub fn run(mode: &str, input: &[u8]) -> (i32, Vec<u8>) {
    // minify parses nothing; handle it before the parse path (as the C does).
    if mode == "minify" {
        return (0, crate::minify(input));
    }
    if mode == "build" {
        let variant = String::from_utf8_lossy(input).trim_end().to_string();
        return match build_variant(&variant) {
            Some(root) => match crate::print_value(&root, false) {
                Some(out) => (0, out),
                None => (RC_USAGE, Vec::new()),
            },
            None => (RC_USAGE, Vec::new()),
        };
    }
    if mode == "query" {
        return query(input);
    }

    let formatted = match mode {
        "print" => true,
        "print-unformatted" | "roundtrip" | "dup" | "dup-eq" => false,
        _ => return (RC_USAGE, Vec::new()),
    };
    let Ok((value, _)) = crate::parse_with_length(input) else {
        return (RC_PARSE, Vec::new());
    };
    match mode {
        "dup" => match crate::print_value(&dom::duplicate(&value), false) {
            Some(out) => (0, out),
            None => (RC_USAGE, Vec::new()),
        },
        "dup-eq" => {
            let dup = dom::duplicate(&value);
            let verdict: &[u8] = if dom::compare(&value, &dup, true) {
                b"true"
            } else {
                b"false"
            };
            (0, verdict.to_vec())
        }
        _ => match crate::print_value(&value, formatted) {
            Some(out) => (0, out),
            None => (RC_USAGE, Vec::new()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_mode_and_variant_are_usage_errors() {
        assert_eq!(run("nope", b"{}"), (RC_USAGE, Vec::new()));
        assert_eq!(run("build", b"nope"), (RC_USAGE, Vec::new()));
    }

    #[test]
    fn query_without_a_newline_is_a_usage_error() {
        assert_eq!(run("query", b"nokey"), (RC_USAGE, Vec::new()));
    }

    #[test]
    fn parse_failure_is_rc1_with_no_stdout() {
        assert_eq!(run("print", b"{"), (RC_PARSE, Vec::new()));
    }
}
