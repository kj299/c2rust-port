//! Module 6 (dom): the in-memory builder/query API, ported from cJSON.c —
//! `cJSON_Create*` (2033–2260), the `Add*` family (2263–2373), the accessors
//! `cJSON_Get*`/`Has*` (1869–1945, 2455+), `cJSON_Duplicate` (2729), and
//! `cJSON_Compare` (3061). This is the surface a consumer uses to build and
//! walk a document; the differential covers it through the driver's `dup` mode
//! (parse → `duplicate` → print) and the FFI increment adds the ABI-level
//! `lib_diff`.
//!
//! **Custom-allocator decision (THREAT-MODEL §5, DIVERGENCES.md): DROPPED.**
//! cJSON's `cJSON_InitHooks`/`global_hooks` is process-global MUTABLE state — a
//! thread-safety hazard the port must not reproduce. The Rust DOM uses the
//! global allocator; there is no `InitHooks` equivalent. Logged as an
//! intentional safety divergence, not a missing feature.
//!
//! `cJSON_Delete` is Rust's `drop` — omitted here because it cannot be gotten
//! wrong (no double-free, no leak). `cJSON_Duplicate` is a recursive clone,
//! which `Value` already derives; the C's reference-flag handling
//! (`create_reference`/`cJSON_IsReference`) is the one DOM feature deferred to
//! the FFI increment, where the C-ABI aliasing semantics actually matter.

use crate::num::compare_double;
use crate::value::{Number, Value};

// ---- constructors (cJSON_Create*) ------------------------------------------

/// Saturating `valuedouble` → `valueint`, the C's rule (cJSON.c:365) applied at
/// construction so a built number prints like a parsed one.
#[must_use]
pub fn number(d: f64) -> Value {
    #[allow(clippy::cast_possible_truncation)] // guarded by the saturation
    let i = if d >= f64::from(i32::MAX) {
        i32::MAX
    } else if d <= f64::from(i32::MIN) {
        i32::MIN
    } else {
        d as i32
    };
    Value::Number(Number { d, i })
}

#[must_use]
pub fn bool_value(b: bool) -> Value {
    if b {
        Value::True
    } else {
        Value::False
    }
}

// ---- accessors (cJSON_Get*/Has*) -------------------------------------------

/// ASCII case-insensitive byte compare, cJSON.c:133 `case_insensitive_strcmp`
/// via `tolower` — used by the case-insensitive object lookup.
fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// cJSON.c:1869 `cJSON_GetArrayItem` — None if not an array or out of range.
#[must_use]
pub fn get_array_item(v: &Value, index: usize) -> Option<&Value> {
    match v {
        Value::Array(items) => items.get(index),
        _ => None,
    }
}

/// cJSON.c:1898 `get_object_item` — FIRST key match (duplicate keys resolve to
/// the first, like the C's list walk), case-sensitive or `tolower`-insensitive.
#[must_use]
pub fn get_object_item<'a>(v: &'a Value, name: &[u8], case_sensitive: bool) -> Option<&'a Value> {
    let Value::Object(entries) = v else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| {
            if case_sensitive {
                k.as_slice() == name
            } else {
                eq_ci(k, name)
            }
        })
        .map(|(_, val)| val)
}

/// cJSON.c `cJSON_GetArraySize` — counts the node's CHILDREN, whatever the node
/// is: the C walks `array->child` and follows `next`, so an *object* reports its
/// member count, not 0.
///
/// This was written as "array length, else 0" from reasoning about the name, and
/// the C refuted it the first time a probe called it on an object
/// (`{"a":{"b":1}}` → `size=1`). Nothing caught it for six gates because no
/// driver mode exercised the accessor — a gate judges only the surface the
/// driver exposes (LESSONS #26; pinned by the generated `probe_query_object`),
/// and the C stays a spec only the oracle can read (LESSONS #17/#21).
#[must_use]
pub fn get_array_size(v: &Value) -> usize {
    match v {
        Value::Array(items) => items.len(),
        Value::Object(entries) => entries.len(),
        _ => 0,
    }
}

// ---- type codes and the struct fields a C caller reads directly ------------

/// The C `type` bitfield (cJSON.h:81–90). A caller that reads `item->type` off
/// the struct sees exactly these numbers.
#[must_use]
pub fn type_code(v: &Value) -> i32 {
    match v {
        Value::False => 1,
        Value::True => 2,
        Value::Null => 4,
        Value::Number(_) => 8,
        Value::String(_) => 16,
        Value::Array(_) => 32,
        Value::Object(_) => 64,
        Value::Raw(_) => 128,
    }
}

/// C `valueint`. **Lossy by construction, and that is the C's behavior:** it is
/// an `int`, so a number above `INT_MAX` saturates (`3000000000` → `2147483647`)
/// and a fractional one truncates toward zero (`-7.5` → `-7`), while
/// `valuedouble` and the printed form stay exact. `cJSON_True` carries
/// `valueint = 1` (cJSON.c:1351); everything else reads 0.
#[must_use]
pub fn value_int(v: &Value) -> i32 {
    match v {
        Value::Number(n) => n.i,
        Value::True => 1,
        _ => 0,
    }
}

/// C `valuestring` — set for strings and raw, NULL for every other type.
#[must_use]
pub fn value_string(v: &Value) -> Option<&[u8]> {
    match v {
        Value::String(s) | Value::Raw(s) => Some(s),
        _ => None,
    }
}

// ---- type predicates (cJSON_Is*) -------------------------------------------

/// `cJSON_IsBool` answers true for BOTH `True` and `False`, so a `true` value
/// satisfies `IsTrue` and `IsBool` at once (probed: flags `TB`).
#[must_use]
pub fn is_bool(v: &Value) -> bool {
    matches!(v, Value::True | Value::False)
}

macro_rules! is_variant {
    ($(#[$m:meta])* $name:ident, $pat:pat) => {
        $(#[$m])*
        #[must_use]
        pub fn $name(v: &Value) -> bool { matches!(v, $pat) }
    };
}

is_variant!(/// `cJSON_IsNull`
            is_null, Value::Null);
is_variant!(/// `cJSON_IsFalse`
            is_false, Value::False);
is_variant!(/// `cJSON_IsTrue`
            is_true, Value::True);
is_variant!(/// `cJSON_IsNumber`
            is_number, Value::Number(_));
is_variant!(/// `cJSON_IsString`
            is_string, Value::String(_));
is_variant!(/// `cJSON_IsRaw`
            is_raw, Value::Raw(_));
is_variant!(/// `cJSON_IsArray`
            is_array, Value::Array(_));
is_variant!(/// `cJSON_IsObject`
            is_object, Value::Object(_));

/// `cJSON_IsInvalid` — `cJSON_Invalid` is type 0, which no live `Value` can be:
/// the enum makes the invalid state unrepresentable, so this is always false.
/// Kept so the predicate set matches the C's one-for-one.
#[must_use]
pub fn is_invalid(_v: &Value) -> bool {
    false
}

// ---- builders (Add*) -------------------------------------------------------

/// cJSON.c:1974 `add_item_to_array`. No-op on a non-array (the C returns false;
/// here a non-array simply isn't mutated).
pub fn add_item_to_array(array: &mut Value, item: Value) -> bool {
    if let Value::Array(items) = array {
        items.push(item);
        true
    } else {
        false
    }
}

/// cJSON.c:2029 `add_item_to_object`. Duplicate keys are appended (not merged),
/// exactly like the C's list — the parser does the same.
pub fn add_item_to_object(object: &mut Value, key: &[u8], item: Value) -> bool {
    if let Value::Object(entries) = object {
        entries.push((key.to_vec(), item));
        true
    } else {
        false
    }
}

/// cJSON.c:2263+ `cJSON_AddStringToObject`.
pub fn add_string_to_object(object: &mut Value, key: &[u8], s: &[u8]) -> bool {
    add_item_to_object(object, key, Value::String(s.to_vec()))
}

/// cJSON.c:2263+ `cJSON_AddNumberToObject` — saturates `valueint` like the
/// parser does.
pub fn add_number_to_object(object: &mut Value, key: &[u8], d: f64) -> bool {
    add_item_to_object(object, key, number(d))
}

/// cJSON.c:2263+ `cJSON_AddBoolToObject`.
pub fn add_bool_to_object(object: &mut Value, key: &[u8], b: bool) -> bool {
    add_item_to_object(object, key, bool_value(b))
}

/// cJSON.c:2263+ `cJSON_AddNullToObject`.
pub fn add_null_to_object(object: &mut Value, key: &[u8]) -> bool {
    add_item_to_object(object, key, Value::Null)
}

// ---- cJSON_Compare (3061) --------------------------------------------------

/// True when a C-string compare would match: byte-equal up to the first NUL on
/// either side (cJSON.c uses `strcmp` on `valuestring`, which stops at NUL).
fn strcmp_eq(a: &[u8], b: &[u8]) -> bool {
    let ca = a.iter().position(|&x| x == 0).unwrap_or(a.len());
    let cb = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    a[..ca] == b[..cb]
}

/// cJSON.c:3061 `cJSON_Compare`. NOT `PartialEq`: numbers compare by
/// `compare_double` (epsilon), strings by NUL-truncated byte compare, objects
/// order-INDEPENDENTLY and bidirectionally (every a-key in b AND every b-key in
/// a — the C's "twice" subset guard), arrays elementwise same-length.
#[must_use]
pub fn compare(a: &Value, b: &Value, case_sensitive: bool) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) | (Value::True, Value::True) | (Value::False, Value::False) => {
            true
        }
        (Value::Number(x), Value::Number(y)) => compare_double(x.d, y.d),
        (Value::String(x), Value::String(y)) | (Value::Raw(x), Value::Raw(y)) => strcmp_eq(x, y),
        (Value::Array(xs), Value::Array(ys)) => {
            xs.len() == ys.len()
                && xs
                    .iter()
                    .zip(ys)
                    .all(|(x, y)| compare(x, y, case_sensitive))
        }
        (Value::Object(ae), Value::Object(be)) => {
            // Bidirectional key subset check (the C's "doing this twice" guard):
            // every a-entry has a matching b-entry AND vice-versa, resolved by
            // get_object_item's first-match rule.
            let subset = |xs: &[(Vec<u8>, Value)], other: &Value| {
                xs.iter().all(|(k, xv)| {
                    get_object_item(other, k, case_sensitive)
                        .is_some_and(|ov| compare(xv, ov, case_sensitive))
                })
            };
            subset(ae, b) && subset(be, a)
        }
        _ => false, // differing types
    }
}

/// cJSON.c:2729 `cJSON_Duplicate` (recurse=true) — a deep clone. `Value`'s
/// derived `Clone` is exactly the recursive copy the C hand-walks.
#[must_use]
pub fn duplicate(v: &Value) -> Value {
    v.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_with_length;
    use crate::print::print_value;

    fn parse(s: &[u8]) -> Value {
        parse_with_length(s).unwrap().0
    }

    #[test]
    fn build_and_print_matches_c() {
        // Build {"a":1,"b":[true,null]} with the DOM API; the printed bytes must
        // equal what the C prints for the same document (observed via oracle).
        let mut arr = Value::Array(vec![]);
        add_item_to_array(&mut arr, Value::True);
        add_item_to_array(&mut arr, Value::Null);
        let mut obj = Value::Object(vec![]);
        add_item_to_object(&mut obj, b"a", number(1.0));
        add_item_to_object(&mut obj, b"b", arr);
        assert_eq!(
            print_value(&obj, false).unwrap(),
            b"{\"a\":1,\"b\":[true,null]}"
        );
    }

    #[test]
    fn accessors() {
        let v = parse(br#"{"a":1,"B":2,"a":3}"#);
        // first duplicate key wins (list-walk semantics)
        assert!(matches!(get_object_item(&v, b"a", true), Some(Value::Number(n)) if n.d == 1.0));
        // case-insensitive finds "B" via "b"
        assert!(get_object_item(&v, b"b", false).is_some());
        assert!(get_object_item(&v, b"b", true).is_none()); // case-sensitive: no "b"
        let arr = parse(b"[10,20,30]");
        assert_eq!(get_array_size(&arr), 3);
        assert!(matches!(get_array_item(&arr, 1), Some(Value::Number(n)) if n.d == 20.0));
        assert!(get_array_item(&arr, 9).is_none());
    }

    #[test]
    fn compare_semantics_match_c() {
        // a value equals its duplicate (the invariant the `dup-eq` differential
        // fuzzes)
        let v = parse(br#"{"a":[1,2,{"x":true}],"b":"hi"}"#);
        assert!(compare(&v, &duplicate(&v), true));
        // objects compare order-independently
        assert!(compare(
            &parse(br#"{"a":1,"b":2}"#),
            &parse(br#"{"b":2,"a":1}"#),
            true
        ));
        // ...but a subset is NOT equal (the C's bidirectional guard)
        assert!(!compare(
            &parse(br#"{"a":1}"#),
            &parse(br#"{"a":1,"b":2}"#),
            true
        ));
        // numbers use epsilon, not bit-equality
        assert!(compare(&number(0.1 + 0.2), &number(0.3), true));
        // differing type
        assert!(!compare(&Value::True, &number(1.0), true));
        // case-sensitive object key mismatch
        assert!(!compare(&parse(br#"{"a":1}"#), &parse(br#"{"A":1}"#), true));
        assert!(compare(&parse(br#"{"a":1}"#), &parse(br#"{"A":1}"#), false));
    }

    #[test]
    fn compare_false_quirks_found_by_dup_eq_differential() {
        // The dup-eq differential's C-baseline validation surfaced two cases
        // where a value does NOT equal its own duplicate in C — the port must
        // reproduce both, not "fix" them:
        //   (1) inf/nan: compare_double(inf, inf) = |inf-inf|<=inf = nan<=inf =
        //       FALSE, so an inf-valued number never compares equal.
        let inf = parse(b"1.79769313486232e+308"); // reparses to inf
        assert!(matches!(&inf, Value::Number(n) if n.d.is_infinite()));
        assert!(!compare(&inf, &duplicate(&inf), true));
        //   (2) duplicate object keys: get_object_item resolves to the FIRST
        //       match, so the second `"a"` can't find its partner → FALSE.
        let dk = parse(br#"{"a":1,"a":2}"#);
        assert!(!compare(&dk, &duplicate(&dk), true));
    }

    #[test]
    fn add_to_wrong_type_is_noop() {
        let mut n = number(1.0);
        assert!(!add_item_to_array(&mut n, Value::Null));
        assert!(!add_item_to_object(&mut n, b"k", Value::Null));
    }
}
