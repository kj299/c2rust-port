//! Module 1 (alloc-node): the JSON tree, C's `struct cJSON` re-expressed as an
//! owned enum.
//!
//! The C node (cJSON.h:105–125) is a doubly-linked sibling list with child
//! pointers, `char *valuestring`, and a type bitfield — every field manually
//! malloc'd/free'd (`cJSON_New_Item`/`cJSON_Delete`, cJSON.c:241–276). Here the
//! tree is owned data: `Vec` children, `String` text, drop = `cJSON_Delete`.
//! That single representational change structurally retires three of the
//! historical bug classes from FLAW-SCAN.md: use-after-free via aliasing (#248),
//! dangling-realloc arbitrary write (#189), and NULL-deref on absent fields
//! (CVE-2024-31755 / CVE-2023-50471/50472) — there is no NULL to deref.
//!
//! C's custom-allocator seam (`global_hooks`, cJSON.c:186 — global MUTABLE
//! state, flagged in THREAT-MODEL.md §5) is deliberately NOT reproduced; the
//! decision on `cJSON_InitHooks` parity is deferred to the FFI/dom module.

/// A number as cJSON stores it (cJSON.h: `valuedouble` + `valueint`): the C
/// keeps BOTH and the printer's integer fast-path compares them
/// (`d == (double)item->valueint`, cJSON.c:573), so the port carries both too —
/// dropping `i` would change printed bytes for integral values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Number {
    /// C `valuedouble`: the full-precision value.
    pub d: f64,
    /// C `valueint`: saturated at parse time (cJSON.c:365–377).
    pub i: i32,
}

/// The JSON tree. Variants mirror the C type bitfield (cJSON.h:81–90).
/// `Object` preserves insertion order and permits duplicate keys, exactly like
/// the C's child list — a map type would silently change observable behavior.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `cJSON_NULL`
    Null,
    /// `cJSON_False`
    False,
    /// `cJSON_True` (the C also sets `valueint = 1`, cJSON.c:1351 — that is
    /// only observable through the DOM API, which arrives with module 6).
    True,
    /// `cJSON_Number`
    Number(Number),
    /// `cJSON_String` — `valuestring` is owned; no NULL state exists.
    ///
    /// BYTES, not `String`: cJSON copies string content verbatim with no UTF-8
    /// validation (probed: a raw 0xFF inside a quoted string round-trips), so
    /// a Rust `String` could not represent every value the C accepts. The
    /// bytes may also contain interior NULs (`\u0000` parses); the C printer
    /// truncates at the first NUL because valuestring is a C string — the
    /// port replicates that at print time (see `string::print_string`).
    String(Vec<u8>),
    /// `cJSON_Raw` — pre-rendered JSON passed through verbatim by the printer.
    Raw(Vec<u8>),
    /// `cJSON_Array` — children in order.
    Array(Vec<Value>),
    /// `cJSON_Object` — (key, value) in insertion order, duplicates allowed;
    /// keys are bytes for the same reason values are.
    Object(Vec<(Vec<u8>, Value)>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_drop_is_delete() {
        // cJSON_Delete walks and frees the whole tree; here dropping the root
        // is the same operation, with double-free/leak unrepresentable.
        let v = Value::Object(vec![
            (b"a".to_vec(), Value::Array(vec![Value::True, Value::Null])),
            (b"a".to_vec(), Value::String(b"dup keys allowed".to_vec())),
        ]);
        drop(v);
    }
}
