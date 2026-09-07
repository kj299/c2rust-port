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
///
/// **INTENTIONAL DIVERGENCE for NaN** (DIVERGENCES.md
/// `create-number-nan-valueint`). Every comparison with a NaN is false, so a NaN
/// falls past both saturation guards and reaches the cast. In C that cast is
/// `(int)num` on a NaN — *undefined behavior* (C17 6.3.1.4p1), and undefined in
/// a way that actually differs per target: x86-64's `cvttsd2si` yields INT_MIN,
/// AArch64's `fcvtzs` yields 0. Rust's `as` is defined to saturate and to map
/// NaN to 0, so the port answers 0 — the defined answer, and the one the C
/// already gives on AArch64.
///
/// Reachable only through construction, never through parsing: `parse_number`
/// has the identical cast but its character whitelist is `0-9 + - e E .`, so
/// `strtod` there can return an infinity (which both guards catch) but never a
/// NaN. That is why six green gates never saw it — until `dom-construct` put
/// `cJSON_CreateDoubleArray` on the compared contract with arbitrary f64 bits.
#[must_use]
pub fn number(d: f64) -> Value {
    #[allow(clippy::cast_possible_truncation)] // guarded by the saturation
    let i = if d >= f64::from(i32::MAX) {
        i32::MAX
    } else if d <= f64::from(i32::MIN) {
        i32::MIN
    } else {
        // NaN lands here and `as` gives 0 — see the divergence note above.
        d as i32
    };
    Value::Number(Number { d, i })
}

/// cJSON.c:2441 `cJSON_CreateBool`.
#[must_use]
pub fn bool_value(b: bool) -> Value {
    if b {
        Value::True
    } else {
        Value::False
    }
}

/// cJSON.c:2430 `cJSON_CreateFalse`. Exported separately by the C even though
/// `cJSON_CreateBool(0)` produces the same node, so it is carried separately
/// here too — the api-coverage gate counts entry points, not behaviors.
#[must_use]
pub fn create_false() -> Value {
    Value::False
}

/// C-string truncation: everything up to the first NUL. cJSON copies text with
/// `cJSON_strdup`, which is `strlen` + `memcpy`, so an interior NUL ends the
/// value regardless of how many bytes the caller thought it was passing
/// (LESSONS #29 — this has to hold at EVERY boundary, not just the printer's).
fn cstr(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())]
}

/// cJSON.c:2528 `cJSON_CreateRaw`. `None` for a NULL argument, mirroring the C:
/// `cJSON_strdup(NULL)` returns NULL, and `cJSON_CreateRaw` then deletes the
/// half-built node and returns NULL rather than a Raw item with a NULL
/// `valuestring` (which the printer would refuse anyway).
#[must_use]
pub fn create_raw(raw: Option<&[u8]>) -> Option<Value> {
    raw.map(|r| Value::Raw(cstr(r).to_vec()))
}

// ---- typed-array constructors (cJSON_Create*Array) -------------------------
//
// The C signatures are `(const T *numbers, int count)` — a pointer and a length
// that the callee has NO way to reconcile. Passing a count larger than the
// buffer is an out-of-bounds read the library cannot detect, and it is the only
// memory-safety hazard these four functions have.
//
// The port takes a SLICE, so the pair cannot disagree: the hazard is designed
// out rather than checked. That improvement is invisible to the differential by
// construction — exercising it would make the C oracle undefined, so there is no
// defined behavior to compare against (DIVERGENCES.md, "Structural
// eliminations"). What the differential DOES compare is everything else: the
// `count < 0` and NULL-pointer guards, the element-by-element saturation of
// `valuedouble` into `valueint`, and the f32 -> f64 widening.
//
// These take a slice and are total; the C's two NULL-returning guards live at
// the driver boundary (`modes::construct`), which is the layer that still has a
// nullable pointer and a signed count to normalize.

/// cJSON.c:2568 `cJSON_CreateIntArray`.
#[must_use]
pub fn create_int_array(numbers: &[i32]) -> Value {
    Value::Array(numbers.iter().map(|&n| number(f64::from(n))).collect())
}

/// cJSON.c:2608 `cJSON_CreateFloatArray`. The C widens each `float` to `double`
/// for `cJSON_CreateNumber`, so `valuedouble` holds the exactly-representable
/// widening of the f32 — not a re-rounded decimal.
#[must_use]
pub fn create_float_array(numbers: &[f32]) -> Value {
    Value::Array(numbers.iter().map(|&n| number(f64::from(n))).collect())
}

/// cJSON.c:2648 `cJSON_CreateDoubleArray`.
#[must_use]
pub fn create_double_array(numbers: &[f64]) -> Value {
    Value::Array(numbers.iter().map(|&n| number(n)).collect())
}

/// cJSON.c:2688 `cJSON_CreateStringArray`. Each element goes through
/// `cJSON_CreateString`, so each is NUL-truncated like `create_raw`.
#[must_use]
pub fn create_string_array(strings: &[&[u8]]) -> Value {
    Value::Array(
        strings
            .iter()
            .map(|s| Value::String(cstr(s).to_vec()))
            .collect(),
    )
}

// ---- accessors (cJSON_Get*/Has*) -------------------------------------------

/// ASCII case-insensitive byte compare, cJSON.c:133 `case_insensitive_strcmp`
/// via `tolower` — used by the case-insensitive object lookup. Like the C, it is
/// a C-string compare: both sides stop at the first NUL (a key `a\0b` matches
/// `a`), consistent with the NUL-truncated string-value compare (`strcmp_eq`).
/// LESSONS #29: key lookup once compared FULL bytes while values and printing
/// truncated at NUL — a latent inconsistency that made `dup-eq` diverge on
/// NUL-collapsing keys until this and `get_object_item` were made C-string too.
fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    let ca = a.iter().position(|&x| x == 0).unwrap_or(a.len());
    let cb = b.iter().position(|&x| x == 0).unwrap_or(b.len());
    a[..ca].eq_ignore_ascii_case(&b[..cb])
}

/// cJSON.c:1869 `cJSON_GetArrayItem` — the index-th entry of the CHILD LIST,
/// whatever the container is.
///
/// It is not array-only, despite the name. The C (cJSON.c:1869) walks
/// `array->child` `index` times with **no type check at all**, so
/// `cJSON_GetArrayItem(obj, 0)` returns an object's first VALUE
/// (`{"a":{"b":1}}` → `{"b":1}`), and a scalar answers NULL only because its
/// `child` is NULL. Reproduced faithfully: it is surprising, but it is
/// memory-safe and it is the contract callers get, so the Prime Directive's
/// fix-the-C clause does not apply.
///
/// This function previously read `Value::Array(items) => items.get(index), _ =>
/// None` — the array-only reading its own doc comment asserted — and no gate
/// disagreed, because nothing called it outside its unit test. The `access`
/// driver mode put it on the compared contract and the C answered differently
/// on the first probe (LESSONS #26/#34: an entry point no mode reaches is
/// ungated, and an assumption no oracle contradicts survives indefinitely).
/// Negative indices never arrive here: `cJSON_GetArrayItem` returns NULL for
/// `index < 0` before calling this, which the caller reproduces.
#[must_use]
pub fn get_array_item(v: &Value, index: usize) -> Option<&Value> {
    match v {
        Value::Array(items) => items.get(index),
        Value::Object(entries) => entries.get(index).map(|(_, value)| value),
        _ => None,
    }
}

/// cJSON.c:1898 `cJSON_HasObjectItem` — `cJSON_GetObjectItem(..) != NULL`, i.e.
/// the CASE-INSENSITIVE lookup, so `has` and a case-sensitive `get` can disagree.
#[must_use]
pub fn has_object_item(v: &Value, name: &[u8]) -> bool {
    get_object_item(v, name, false).is_some()
}

/// cJSON.c `cJSON_GetStringValue` — `valuestring` for strings, NULL otherwise.
///
/// NOT the same as [`value_string`], which also answers for `Raw` (both set the
/// C's `valuestring` field, but this accessor gates on `cJSON_IsString` alone).
/// Tolerates a "NULL" item — the C checks `cJSON_IsString(NULL)`, which is
/// false — which is why the driver mode feeds it lookup results directly.
#[must_use]
pub fn get_string_value(v: Option<&Value>) -> Option<&[u8]> {
    match v {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

/// cJSON.c `cJSON_GetNumberValue` — `valuedouble`, or **NaN** for anything that
/// is not a number, NULL included. Returning NaN rather than an error means a
/// caller that skips the type check silently propagates NaN, so the driver mode
/// spells NaN out rather than encoding its bits (many patterns, one meaning).
#[must_use]
pub fn get_number_value(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Number(n)) => n.d,
        _ => f64::NAN,
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
                // C-string compare (strcmp): both sides truncate at the first NUL.
                strcmp_eq(k, name)
            } else {
                eq_ci(k, name)
            }
        })
        .map(|(_, val)| val)
}

/// [`get_object_item`], but handing back a mutable borrow so the in-place
/// setters can be applied to a member of a parsed document.
///
/// In C this distinction does not exist: `cJSON_GetObjectItem` returns a plain
/// `cJSON *` and the caller may write through it whenever it likes, including
/// after the document has been freed. Here the returned borrow keeps the
/// document alive and exclusive for exactly as long as it is held, which is what
/// makes `cJSON_SetValuestring`'s aliasing hazard unspellable (see
/// [`set_valuestring`]).
#[must_use]
pub fn get_object_item_mut<'a>(
    v: &'a mut Value,
    name: &[u8],
    case_sensitive: bool,
) -> Option<&'a mut Value> {
    let Value::Object(entries) = v else {
        return None;
    };
    entries
        .iter_mut()
        .find(|(k, _)| {
            if case_sensitive {
                strcmp_eq(k, name)
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

/// C `valuedouble`. Every node the C builds comes from `cJSON_New_Item`, which
/// `memset`s the struct to zero, and only `parse_number` / `cJSON_CreateNumber`
/// / `cJSON_SetNumberHelper` ever write the field — so a non-number reads 0.0.
///
/// The port's enum reproduces that for every node it can build. The one place it
/// cannot is `cJSON_SetNumberHelper`, which writes `valuedouble` (and
/// `valueint`) with **no type check at all**, leaving a `cJSON_String` node
/// carrying a number. See [`set_number`] — that is a ledgered divergence, and
/// this accessor is how the `set` driver mode makes it visible.
#[must_use]
pub fn value_double(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.d,
        _ => 0.0,
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

// ---- in-place setters (cJSON_Set*) -----------------------------------------

/// cJSON.c:403 `cJSON_SetValuestring` — replace a string node's text in place.
/// `None` for a non-string target or a `None` replacement, matching the C's two
/// NULL-returning guards; otherwise the new (NUL-truncated) bytes.
///
/// **Three of the C's behaviors are designed out rather than reproduced**, and
/// the differential cannot see any of them, which is why they are written here:
///
/// 1. **The overlapping `strcpy` (cJSON.c:418) — a live UB defect.** The C's
///    "new is no longer than old" fast path is
///    `strcpy(object->valuestring, valuestring)`, and nothing stops the caller
///    passing a pointer *into that same buffer* — `cJSON_SetValuestring(item,
///    item->valuestring + 2)` is a plausible "strip a prefix" call and is an
///    overlapping copy, undefined per C17 7.24.2.3. Not theoretical: ASan
///    reports `memcpy-param-overlap` at cJSON.c:418 (`spikes/setvaluestring_alias.c`,
///    FLAW-SCAN.md L4). Here the target is `&mut Value` and the replacement is a
///    separate slice, so a caller cannot name both at once — the borrow checker
///    rejects it at compile time.
/// 2. **The `object->valuestring == NULL` guard** is unreachable for the port:
///    `Value::String` always owns its bytes, and the only C nodes that can carry
///    a NULL `valuestring` while claiming to be strings come from
///    `cJSON_CreateStringReference`, which API-COVERAGE.md refuses as
///    out-of-scope.
/// 3. **The `cJSON_IsReference` guard**, for the same reason — the port never
///    builds a borrowed-pointer node.
///
/// What the differential DOES compare is the observable result: which calls
/// answer NULL, and what the node's text is afterwards. The C's length branch is
/// crossed in both directions by the `set` driver mode but is not
/// *distinguishable* from outside — both paths leave `valuestring` equal to the
/// new C string and return it (DIVERGENCES.md, "Structural eliminations").
pub fn set_valuestring<'a>(v: &'a mut Value, s: Option<&[u8]>) -> Option<&'a [u8]> {
    let s = s?;
    match v {
        Value::String(cur) => {
            // `cstr`, not the whole slice: the C copies with `strcpy`, so an
            // interior NUL ends the value here exactly as it does in every
            // other constructor (LESSONS #29).
            //
            // Unlike the other boundaries, this one is a CANONICALIZATION the
            // differential cannot see, and saying so beats implying otherwise.
            // Deleting the `cstr` was injected deliberately and the `set` matrix
            // stayed green: the C physically cannot store an interior NUL here
            // (it arrives through a `const char *`), and every reader on both
            // sides — the printer, `strcmp_eq`, the descriptor's `sb_bytes`
            // counterpart — truncates, so the extra bytes are unreachable. It is
            // still right to drop them: `Value` equality and any future
            // full-bytes consumer would otherwise see a state parsing can
            // produce but this setter should not. Pinned by
            // `set_valuestring_truncates_at_a_nul`, which is the only thing
            // holding it.
            *cur = cstr(s).to_vec();
            Some(cur.as_slice())
        }
        _ => None,
    }
}

/// cJSON.c:384 `cJSON_SetNumberHelper` — the function behind the
/// `cJSON_SetNumberValue` macro. Returns the number it was given, as the C does
/// (`return object->valuedouble = number;`).
///
/// **INTENTIONAL DIVERGENCE: the C performs NO TYPE CHECK.** It writes
/// `valueint` and `valuedouble` into whatever node it is handed, so
/// `cJSON_SetNumberValue(a_string_node, 5)` leaves a node whose `type` says
/// `cJSON_String` and whose `valuedouble` says 5 — a type-confused state no
/// accessor will ever report (`cJSON_GetNumberValue` checks `cJSON_IsNumber`
/// first) but that any caller reading the public struct fields will see. The
/// port cannot represent it: `Value::String` has no number to write. So the
/// operation is a no-op on a non-number, which is also the safer answer — the
/// inconsistent state is unrepresentable rather than merely undocumented.
/// Ledgered as `set-*-type-confusion` (6 rows) and pinned by the `set` matrix,
/// which shows the target's `type`/`valueint`/`valuedouble` precisely so the
/// divergence is measured rather than asserted (LESSONS #31).
///
/// Nobody found this by reading. The mutation spike read this same function
/// twice — H4 for its missing NULL check, H5 for the NaN cast below — and
/// neither pass noticed the missing type check; the `set` driver mode's first
/// non-number target did (LESSONS #38).
///
/// **INTENTIONAL DIVERGENCE for NaN**, identical to [`number`]'s: a NaN falls
/// past both of the C's saturation guards into `(int)number`, which is UB
/// (C17 6.3.1.4p1) and answers INT_MIN on x86-64 and 0 on AArch64. Sharing
/// [`number`] is what gives the port the defined answer here for free —
/// DIVERGENCES.md `set-number-nan-valueint`.
///
/// **STRUCTURAL ELIMINATION: the missing NULL check.** The exported symbol
/// dereferences `object` immediately; only the macro guards it, so a caller who
/// links against `cJSON_SetNumberHelper` (it is `CJSON_PUBLIC`) gets a
/// NULL-deref. `&mut Value` has no null state, so the hazard does not exist
/// here — and it cannot be differentially tested either, because the C's answer
/// to it is a segfault, not a value.
pub fn set_number(v: &mut Value, d: f64) -> f64 {
    if matches!(v, Value::Number(_)) {
        *v = number(d);
    }
    d
}

// ---- builders (Add*) -------------------------------------------------------

/// cJSON.c:1974 `add_item_to_array`.
///
/// **The C does NOT check that `array` is an array.** Its only guards are
/// `item == NULL`, `array == NULL` and `array == item`; after those it appends
/// straight onto `array->child`, so `cJSON_AddItemToArray(number_node, item)`
/// succeeds and hangs a child off a *scalar*. Probed against v1.7.18: the
/// printer ignores that child (a number still prints `7`), but
/// `cJSON_GetArraySize` then answers 1 and `cJSON_GetArrayItem(node, 0)` hands
/// it back — so the malformed tree is observable, not inert.
///
/// This function used to claim the C "returns false" for a non-array. It does
/// not. That was the third doc comment in this file to assert a type check the
/// C never performs (`get_array_size` and `get_array_item` were the first two,
/// and both shipped wrong because of it) — LESSONS #36: a doc comment stating a
/// constraint is a claim, and an unreached claim never gets audited.
///
/// The port cannot reproduce it: `Value::Number` has nowhere to put a child, so
/// a malformed tree is unrepresentable rather than merely rejected. Returning
/// false here is the closest observable equivalent. Putting the non-container
/// parent on the compared contract is its own increment — see DIVERGENCES.md
/// `scalar-parent-child`.
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
///
/// Same missing type check as `add_item_to_array`, which this delegates to in
/// the C: `object` is never tested for being an object, so every
/// `cJSON_Add*ToObject` helper succeeds on an array, a number, a string, even
/// `null`. See `add_item_to_array` and DIVERGENCES.md `scalar-parent-child`.
pub fn add_item_to_object(object: &mut Value, key: &[u8], item: Value) -> bool {
    add_named(object, key, item).is_some()
}

/// Shared body of the `cJSON_Add*ToObject` family: append and hand back the
/// item just added, which is what the C returns so a caller can keep building
/// into a freshly-added container.
fn add_named<'a>(object: &'a mut Value, key: &[u8], item: Value) -> Option<&'a mut Value> {
    if let Value::Object(entries) = object {
        entries.push((key.to_vec(), item));
        entries.last_mut().map(|(_, v)| v)
    } else {
        None
    }
}

/// cJSON.c:2109 `cJSON_AddTrueToObject`.
pub fn add_true_to_object<'a>(object: &'a mut Value, key: &[u8]) -> Option<&'a mut Value> {
    add_named(object, key, Value::True)
}

/// cJSON.c:2121 `cJSON_AddFalseToObject`.
pub fn add_false_to_object<'a>(object: &'a mut Value, key: &[u8]) -> Option<&'a mut Value> {
    add_named(object, key, create_false())
}

/// cJSON.c:2169 `cJSON_AddRawToObject`. A NULL `raw` makes `cJSON_CreateRaw`
/// return NULL, and the C then adds NOTHING and answers NULL — so `None` here
/// means the object is left untouched, not that an empty Raw was appended.
pub fn add_raw_to_object<'a>(
    object: &'a mut Value,
    key: &[u8],
    raw: Option<&[u8]>,
) -> Option<&'a mut Value> {
    add_named(object, key, create_raw(raw)?)
}

/// cJSON.c:2181 `cJSON_AddObjectToObject`.
pub fn add_object_to_object<'a>(object: &'a mut Value, key: &[u8]) -> Option<&'a mut Value> {
    add_named(object, key, Value::Object(Vec::new()))
}

/// cJSON.c:2193 `cJSON_AddArrayToObject`.
pub fn add_array_to_object<'a>(object: &'a mut Value, key: &[u8]) -> Option<&'a mut Value> {
    add_named(object, key, Value::Array(Vec::new()))
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
    fn get_array_item_walks_an_objects_children_too() {
        // THE REGRESSION for the `access` module's first finding (LESSONS #26):
        // cJSON_GetArrayItem is not array-only. The C walks `->child` with no
        // type check, so an OBJECT answers by position. This function used to
        // return None here — matching its own doc comment and not the C — and
        // no gate disagreed for six gates, because nothing outside this test
        // ever called it. Pinned in the same change that fixed it.
        let obj = parse(br#"{"a":1,"b":{"c":2},"d":3}"#);
        assert!(matches!(get_array_item(&obj, 0), Some(Value::Number(n)) if n.d == 1.0));
        assert!(matches!(get_array_item(&obj, 1), Some(Value::Object(_))));
        assert!(matches!(get_array_item(&obj, 2), Some(Value::Number(n)) if n.d == 3.0));
        assert!(get_array_item(&obj, 3).is_none());
        // a scalar has no child list at all, which is the only reason the C's
        // missing type check is safe
        assert!(get_array_item(&parse(b"42"), 0).is_none());
        assert!(get_array_item(&parse(br#""hi""#), 0).is_none());
    }

    #[test]
    fn typed_accessors_tolerate_a_null_item() {
        // cJSON_GetStringValue/GetNumberValue route through cJSON_IsString/
        // IsNumber, which answer false for NULL — so a caller that skips the
        // lookup's NULL check gets NULL/NaN rather than a crash. That
        // tolerance is contract, which is why the driver mode feeds them
        // lookup results directly.
        assert!(get_string_value(None).is_none());
        assert!(get_number_value(None).is_nan());
        let s = parse(br#""text""#);
        let n = parse(b"2.5");
        assert_eq!(get_string_value(Some(&s)), Some(&b"text"[..]));
        assert!(get_string_value(Some(&n)).is_none()); // wrong type -> NULL
        assert!((get_number_value(Some(&n)) - 2.5).abs() < f64::EPSILON);
        assert!(get_number_value(Some(&s)).is_nan()); // wrong type -> NaN
                                                      // Raw sets the C's `valuestring` field, but GetStringValue gates on
                                                      // cJSON_IsString alone, so it declines — unlike `value_string`.
        let raw = Value::Raw(b"{}".to_vec());
        assert!(get_string_value(Some(&raw)).is_none());
        assert!(value_string(&raw).is_some());
    }

    #[test]
    fn has_object_item_is_the_case_insensitive_lookup() {
        let v = parse(br#"{"Key":1}"#);
        assert!(has_object_item(&v, b"key"));
        assert!(has_object_item(&v, b"KEY"));
        // ...so `has` and a case-SENSITIVE get legitimately disagree
        assert!(get_object_item(&v, b"key", true).is_none());
        assert!(!has_object_item(&v, b"nope"));
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

    /// The port refuses a non-container parent. **The C does not** — probed
    /// against v1.7.18, `cJSON_AddTrueToObject` succeeds on an array, a number,
    /// a string, `true` and `null` alike, and `cJSON_GetArrayItem(node, 0)` then
    /// hands the child back. See `add_item_to_array` and DIVERGENCES.md
    /// `scalar-parent-child`: this is a refusal, not a match, and it is not yet
    /// on the compared contract.
    #[test]
    fn add_to_wrong_type_is_noop() {
        let mut n = number(1.0);
        assert!(!add_item_to_array(&mut n, Value::Null));
        assert!(!add_item_to_object(&mut n, b"k", Value::Null));
        assert!(add_true_to_object(&mut n, b"k").is_none());
        assert!(add_array_to_object(&mut n, b"k").is_none());
    }

    /// The intentional divergence, pinned where it is made
    /// (DIVERGENCES.md `create-number-nan-valueint`). The C's `(int)NaN` is
    /// undefined and answers INT_MIN on x86-64, 0 on AArch64; the port always
    /// answers 0.
    #[test]
    fn nan_valueint_is_zero_not_the_platform_s_undefined_answer() {
        assert!(matches!(number(f64::NAN), Value::Number(n) if n.i == 0));
        assert!(matches!(number(-f64::NAN), Value::Number(n) if n.i == 0));
        // ...while the infinities take the C's guards and are perfectly defined.
        assert!(matches!(number(f64::INFINITY), Value::Number(n) if n.i == i32::MAX));
        assert!(matches!(number(f64::NEG_INFINITY), Value::Number(n) if n.i == i32::MIN));
    }

    #[test]
    fn typed_array_constructors_saturate_per_element() {
        let Value::Array(items) = create_double_array(&[2147483647.0, -1e300, 0.5]) else {
            panic!("not an array");
        };
        let ints: Vec<i32> = items.iter().map(value_int).collect();
        assert_eq!(ints, vec![i32::MAX, i32::MIN, 0]);
        // (double)int is lossless, so an int array never actually saturates.
        let Value::Array(items) = create_int_array(&[i32::MIN, i32::MAX]) else {
            panic!("not an array");
        };
        assert_eq!(
            items.iter().map(value_int).collect::<Vec<_>>(),
            vec![i32::MIN, i32::MAX]
        );
        // ...but a float array does, because f32 -> f64 is exact and f32 can
        // hold values far outside i32.
        let Value::Array(items) = create_float_array(&[3.4e38, f32::NEG_INFINITY]) else {
            panic!("not an array");
        };
        assert_eq!(
            items.iter().map(value_int).collect::<Vec<_>>(),
            vec![i32::MAX, i32::MIN]
        );
    }

    /// LESSONS #29: C-string truncation has to hold at EVERY boundary. Both
    /// `cJSON_CreateRaw` and `cJSON_CreateString` copy with `cJSON_strdup`,
    /// which is `strlen` + `memcpy`.
    #[test]
    fn raw_and_string_elements_truncate_at_a_nul() {
        assert_eq!(
            create_raw(Some(b"ab\0cd")),
            Some(Value::Raw(b"ab".to_vec()))
        );
        assert_eq!(create_raw(None), None);
        let Value::Array(items) = create_string_array(&[b"x\0y", b"", b"z"]) else {
            panic!("not an array");
        };
        let got: Vec<&[u8]> = items.iter().filter_map(value_string).collect();
        assert_eq!(got, vec![&b"x"[..], &b""[..], &b"z"[..]]);
    }

    /// A NULL `raw` makes `cJSON_CreateRaw` return NULL, and the C then adds
    /// NOTHING rather than an empty Raw — the object must be left untouched.
    #[test]
    fn add_raw_to_object_with_a_null_raw_adds_nothing() {
        let mut root = Value::Object(Vec::new());
        assert!(add_raw_to_object(&mut root, b"k", None).is_none());
        assert_eq!(root, Value::Object(Vec::new()));
        assert!(add_raw_to_object(&mut root, b"k", Some(b"")).is_some());
        assert_eq!(get_array_size(&root), 1);
    }

    /// An empty Raw prints as nothing at all, so the object renders `{"k":}` —
    /// invalid JSON that cJSON emits happily, and the port must too.
    #[test]
    fn empty_raw_prints_as_nothing() {
        let mut root = Value::Object(Vec::new());
        add_raw_to_object(&mut root, b"k", Some(b""));
        assert_eq!(print_value(&root, false).unwrap(), br#"{"k":}"#.to_vec());
        let mut root = Value::Object(Vec::new());
        add_raw_to_object(&mut root, b"k", Some(br#"{"unescaped":"quotes"}"#));
        assert_eq!(
            print_value(&root, false).unwrap(),
            br#"{"k":{"unescaped":"quotes"}}"#.to_vec()
        );
    }

    /// DIVERGENCES.md `set-*-type-confusion`. The C writes `valueint` and
    /// `valuedouble` into whatever node it is handed; the port refuses, so the
    /// node stays exactly what it was. The RETURN value still matches the C's
    /// (`return object->valuedouble = number` gives back `number` either way),
    /// which is why only the struct-field view of the target diverges.
    #[test]
    fn set_number_on_a_non_number_leaves_the_node_alone_but_returns_the_number() {
        for mut v in [
            Value::String(b"text".to_vec()),
            Value::True,
            Value::Null,
            Value::Array(vec![Value::Null]),
            Value::Object(Vec::new()),
            Value::Raw(b"1".to_vec()),
        ] {
            let before = v.clone();
            assert_eq!(set_number(&mut v, 3.0), 3.0);
            assert_eq!(v, before, "set_number must not touch a non-number");
            assert_eq!(value_double(&v), 0.0);
        }
        // ...and on a real number it does the whole job.
        let mut n = number(1.0);
        assert_eq!(set_number(&mut n, -7.5), -7.5);
        assert_eq!(value_int(&n), -7);
        assert_eq!(value_double(&n), -7.5);
    }

    /// DIVERGENCES.md `set-nan-*`: the second site of the `(int)NaN` cast. The
    /// port answers the DEFINED 0 rather than x86-64's INT_MIN, and it does so
    /// by sharing one helper with `cJSON_CreateNumber` rather than by having a
    /// second copy of the rule that could drift.
    #[test]
    fn set_number_nan_valueint_is_zero_at_this_site_too() {
        for nan in [f64::NAN, -f64::NAN, f64::from_bits(0x7ff0_0000_0000_0001)] {
            let mut n = number(1.0);
            set_number(&mut n, nan);
            assert_eq!(value_int(&n), 0);
            assert!(value_double(&n).is_nan());
        }
    }

    /// The saturation guards are `>=` and `<=`, so both boundaries land on the
    /// guard rather than on the cast (cJSON.c:386-395).
    #[test]
    fn set_number_saturation_boundaries_are_inclusive() {
        let mut n = number(0.0);
        set_number(&mut n, f64::from(i32::MAX));
        assert_eq!(value_int(&n), i32::MAX);
        set_number(&mut n, f64::from(i32::MIN));
        assert_eq!(value_int(&n), i32::MIN);
        set_number(&mut n, f64::INFINITY);
        assert_eq!(value_int(&n), i32::MAX);
        set_number(&mut n, f64::NEG_INFINITY);
        assert_eq!(value_int(&n), i32::MIN);
    }

    /// Both of the C's NULL-returning guards, and the fact that a refused call
    /// changes nothing.
    #[test]
    fn set_valuestring_refuses_a_non_string_or_a_missing_replacement() {
        let mut n = number(1.0);
        assert!(set_valuestring(&mut n, Some(b"x")).is_none());
        assert_eq!(n, number(1.0));

        let mut s = Value::String(b"keep".to_vec());
        assert!(set_valuestring(&mut s, None).is_none());
        assert_eq!(s, Value::String(b"keep".to_vec()));
    }

    /// LESSONS #29 at this boundary too: the C copies with `strcpy`, so an
    /// interior NUL ends the value however many bytes the caller passed.
    ///
    /// **This test is the only thing pinning it.** Removing the `cstr` call was
    /// injected into the port deliberately and the `set` differential stayed
    /// green over all 52 matrix rows — the C cannot represent the difference and
    /// every reader truncates, so it is a canonicalization rather than an
    /// observable behavior. Which is exactly why it needs a unit test: the gate
    /// that would normally catch a regression here cannot.
    #[test]
    fn set_valuestring_truncates_at_a_nul() {
        let mut s = Value::String(b"original".to_vec());
        assert_eq!(set_valuestring(&mut s, Some(b"ab\0cd")), Some(&b"ab"[..]));
        assert_eq!(s, Value::String(b"ab".to_vec()));
    }

    /// The C picks between an in-place `strcpy` and a fresh allocation on
    /// `strlen(new) <= strlen(old)`. Both sides must leave the same value, which
    /// is the whole reason the branch is invisible to the differential — pinned
    /// here so a future port that grows two paths has to keep them agreeing.
    ///
    /// The C's in-place path is also where its overlapping-`strcpy` UB lives
    /// (FLAW-SCAN.md L4). There is no test for that here because there is
    /// nothing to test: `set_valuestring(&mut v, Some(<bytes borrowed from v>))`
    /// does not compile, which is the entire fix.
    #[test]
    fn set_valuestring_gives_the_same_answer_on_both_sides_of_the_length_branch() {
        // shorter than the old value: the C reuses the buffer
        let mut short = Value::String(b"0123456789".to_vec());
        assert_eq!(set_valuestring(&mut short, Some(b"ab")), Some(&b"ab"[..]));
        // longer: the C allocates a new one and frees the old
        let mut long = Value::String(b"a".to_vec());
        assert_eq!(set_valuestring(&mut long, Some(b"ab")), Some(&b"ab"[..]));
        assert_eq!(short, long);
        // exactly equal: `<=` puts this on the in-place side
        let mut eq = Value::String(b"xy".to_vec());
        assert_eq!(set_valuestring(&mut eq, Some(b"ab")), Some(&b"ab"[..]));
        assert_eq!(eq, long);
    }

    /// `get_object_item_mut` must resolve duplicate keys the way the C's list
    /// walk does — first match wins — or a setter would land on the wrong node.
    #[test]
    fn get_object_item_mut_takes_the_first_duplicate_key() {
        let mut root = Value::Object(vec![
            (b"k".to_vec(), number(1.0)),
            (b"k".to_vec(), number(2.0)),
        ]);
        let target = get_object_item_mut(&mut root, b"k", true).unwrap();
        set_number(target, 9.0);
        assert_eq!(
            print_value(&root, false).unwrap(),
            br#"{"k":9,"k":2}"#.to_vec()
        );
        // ...and it is case-sensitive when asked to be, like its shared-name
        // read-only twin.
        assert!(get_object_item_mut(&mut root, b"K", true).is_none());
        assert!(get_object_item_mut(&mut root, b"K", false).is_some());
    }
}
