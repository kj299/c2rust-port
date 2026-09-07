//! The differential driver's mode dispatch, as library code.
//!
//! `oracle/driver.c` defines a byte-for-byte contract (mode + stdin → stdout +
//! exit code) that the Rust side must match. That contract was implemented
//! TWICE on the Rust side — once in `crates/driver` (what `diff_run` executes)
//! and once in the probe-test glue (what the generated `probes_*.rs` tests
//! call) — so the two could drift and the tests would then be measuring
//! something the differential does not.
//!
//! The `build`/`query` modes exist for LESSONS #26: a gate judges only the
//! surface the driver exposes, and until they landed the builder/query/accessor
//! API was off the compared contract entirely — which is how `get_array_size`
//! shipped wrong through six green gates.
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

/// A double as the `access` descriptor spells it: `nan`, else the raw IEEE-754
/// bits in lowercase hex. Never a formatted float — `%g` vs Rust's `{}` would
/// make the compared contract "libc's float formatter" rather than the accessor,
/// and the bits also preserve the sign of `-0.0`, which the printed form loses.
fn encode_double(d: f64) -> String {
    if d.is_nan() {
        "nan".to_string()
    } else {
        format!("{:016x}", d.to_bits())
    }
}

/// The driver's index normalization, matching `driver.c`'s `strtol` + clamp:
/// leading spaces, an optional sign, then decimal digits; junk reads as 0 and an
/// out-of-range value saturates. This is DRIVER contract, not cJSON contract —
/// the fuzzer sends non-numeric and overflowing indices, and both sides have to
/// turn them into the same `int` before `cJSON_GetArrayItem` ever sees them.
fn parse_index(field: &[u8]) -> i32 {
    let s = field.split(|&b| b == 0).next().unwrap_or(field);
    let text = String::from_utf8_lossy(s);
    let t = text.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    // i64 then clamp: parsing straight to i32 would make an overflowing literal
    // an Err (→ 0), where C's strtol saturates to LONG_MAX and the driver clamps
    // that to INT_MAX. Same reason the digit run is capped before parsing.
    let run = digits.get(..end.min(18)).unwrap_or("");
    let magnitude: i64 = run.parse().unwrap_or(0);
    // `checked_neg` and `try_from`, not `-x` and `as i32`: the workspace denies
    // arithmetic_side_effects and cast_possible_truncation, and a silent
    // wraparound here would turn a fuzzed index into a valid one — the exact
    // class of C bug this port exists to remove. The clamp makes try_from
    // total, so the fallback is unreachable rather than a swallowed error.
    let signed = if neg {
        magnitude.checked_neg().unwrap_or(i64::MIN)
    } else {
        magnitude
    };
    i32::try_from(signed.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0)
}

/// `access`: stdin is `<key>\t<index>\n<json>` — the five accessor entry points
/// in one shot (`cJSON_GetObjectItem` case-INsensitive, `cJSON_HasObjectItem`,
/// `cJSON_GetArrayItem`, `cJSON_GetStringValue`, `cJSON_GetNumberValue`).
///
/// The string/number accessors are fed the lookup RESULTS, `None` included,
/// because tolerating a NULL item is part of their contract in the C.
fn access(input: &[u8]) -> (i32, Vec<u8>) {
    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
        return (RC_USAGE, Vec::new());
    };
    let (head, rest) = input.split_at(nl);
    let json = rest.get(1..).unwrap_or(&[]);
    let Some(tab) = head.iter().position(|&b| b == b'\t') else {
        return (RC_USAGE, Vec::new());
    };
    let (key, idx_field) = head.split_at(tab);
    let index = parse_index(idx_field.get(1..).unwrap_or(&[]));

    let Ok((value, _)) = crate::parse_with_length(json) else {
        return (RC_PARSE, Vec::new());
    };

    let by_key = dom::get_object_item(&value, key, false);
    let has = dom::has_object_item(&value, key);
    // `index < 0` answers None before the child walk (cJSON.c:1889), so the
    // cast is only ever reached for a non-negative value.
    let by_idx = if index < 0 {
        None
    } else {
        dom::get_array_item(&value, index.unsigned_abs() as usize)
    };

    let mut out = Vec::new();
    out.extend_from_slice(format!("has={};kobj=", i32::from(has)).as_bytes());
    push_printed(&mut out, by_key);
    out.extend_from_slice(b";kstr=");
    push_cstr(&mut out, dom::get_string_value(by_key));
    out.extend_from_slice(
        format!(
            ";knum={};iarr=",
            encode_double(dom::get_number_value(by_key))
        )
        .as_bytes(),
    );
    push_printed(&mut out, by_idx);
    out.extend_from_slice(b";istr=");
    push_cstr(&mut out, dom::get_string_value(by_idx));
    out.extend_from_slice(
        format!(";inum={}", encode_double(dom::get_number_value(by_idx))).as_bytes(),
    );
    (0, out)
}

/// Element cap for `construct`, matching `MAX_ELEMS` in `cjson_modes.c`. It
/// bounds the descriptor whatever the fuzzer sends and costs no coverage: the
/// saturation logic these constructors perform is per element, and the one thing
/// a bigger count could reach — a count past the end of the buffer — is
/// undefined behavior in the C, so there is no defined answer to compare to.
const CONSTRUCT_MAX_ELEMS: usize = 16;

/// The C driver's `strtol` + clamp on the count field, then
/// `cjson_modes_construct`'s clamp to what the payload actually holds. A
/// negative count survives (it is the C's `count < 0` → NULL guard); a positive
/// one is never allowed past `avail`.
fn construct_count(count: i32, avail: usize) -> Option<usize> {
    if count < 0 {
        return None;
    }
    let n = usize::try_from(count).unwrap_or(0);
    Some(n.min(avail))
}

/// `construct`: stdin is `<count>\t<name>\t<raw>\n<payload>` — the twelve
/// constructor entry points in one shot.
///
/// `payload` supplies the elements as whole little-endian groups from DISJOINT
/// thirds — ints, then doubles, then floats — while the string array reads the
/// whole payload split on NUL. An EMPTY region is how the C's NULL-pointer guard
/// is reached, since a null pointer is the one thing a slice cannot express.
fn construct(input: &[u8]) -> (i32, Vec<u8>) {
    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
        return (RC_USAGE, Vec::new());
    };
    let (head, rest) = input.split_at(nl);
    let payload = rest.get(1..).unwrap_or(&[]);
    let Some(t1) = head.iter().position(|&b| b == b'\t') else {
        return (RC_USAGE, Vec::new());
    };
    let (count_field, after) = head.split_at(t1);
    let after = after.get(1..).unwrap_or(&[]);
    let Some(t2) = after.iter().position(|&b| b == b'\t') else {
        return (RC_USAGE, Vec::new());
    };
    let (name_field, raw_field) = after.split_at(t2);
    let raw_field = raw_field.get(1..).unwrap_or(&[]);

    // The C reads `name` and `raw` as C strings out of a buffer it NUL-split,
    // so both truncate at an interior NUL before cJSON ever sees them.
    let name = cstr_prefix(name_field);
    let raw = cstr_prefix(raw_field);
    let count = parse_index(count_field);

    // The three number arrays read DISJOINT thirds — ints, then doubles, then
    // floats — so no two of them reinterpret the same bytes at different
    // widths. Sharing one buffer made whole classes of case unprobeable: an f64
    // infinity is `7F F0 00 .. 00`, whose high four bytes are an f32 NaN, and an
    // INT_MIN/INT_MAX pair is the f64 `0x7FFFFFFF80000000` — also a NaN. So
    // every interesting value forced a NaN into a sibling array, and NaN is the
    // one value this mode cannot put in a probe (it is the ledgered
    // divergence). The coupling was the harness's, not cJSON's.
    let third = payload.len() / 3;
    let i_reg = payload.get(..third).unwrap_or(&[]);
    let d_reg = payload.get(third..third.saturating_mul(2)).unwrap_or(&[]);
    let g_reg = payload.get(third.saturating_mul(2)..).unwrap_or(&[]);

    // `chunks_exact` yields only WHOLE groups, matching the C's
    // `len / sizeof(T)` — a trailing partial group is dropped, never padded.
    let ints: Vec<i32> = i_reg
        .chunks_exact(4)
        .take(CONSTRUCT_MAX_ELEMS)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    let doubles: Vec<f64> = d_reg
        .chunks_exact(8)
        .take(CONSTRUCT_MAX_ELEMS)
        .map(|c| f64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
        .collect();
    let floats: Vec<f32> = g_reg
        .chunks_exact(4)
        .take(CONSTRUCT_MAX_ELEMS)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    // `split` on NUL gives count(NUL)+1 fields, matching the C's walk over a
    // NUL-terminated private copy of the WHOLE payload.
    let strings: Vec<&[u8]> = payload
        .split(|&b| b == 0)
        .take(CONSTRUCT_MAX_ELEMS)
        .collect();

    // Each array's pointer is NULL iff its OWN region is empty, so the C's
    // `numbers == NULL` guard is reachable per array rather than
    // all-or-nothing: a 1-byte payload gives the int and double arrays NULL and
    // the float array a non-NULL pointer with zero whole elements.
    let arr_i = (!i_reg.is_empty())
        .then(|| construct_count(count, ints.len()))
        .flatten()
        .map(|n| dom::create_int_array(ints.get(..n).unwrap_or(&[])));
    let arr_d = (!d_reg.is_empty())
        .then(|| construct_count(count, doubles.len()))
        .flatten()
        .map(|n| dom::create_double_array(doubles.get(..n).unwrap_or(&[])));
    let arr_g = (!g_reg.is_empty())
        .then(|| construct_count(count, floats.len()))
        .flatten()
        .map(|n| dom::create_float_array(floats.get(..n).unwrap_or(&[])));
    let arr_s = (!payload.is_empty())
        .then(|| construct_count(count, strings.len()))
        .flatten()
        .map(|n| dom::create_string_array(strings.get(..n).unwrap_or(&[])));

    let fal = dom::create_false();
    let boo = dom::bool_value(count != 0);
    let rw = dom::create_raw(Some(raw));

    // All five Add*ToObject calls use the SAME key on purpose: cJSON APPENDS a
    // duplicate key rather than replacing it, so one input covers both paths.
    let mut root = Value::Object(Vec::new());
    let ok_t = dom::add_true_to_object(&mut root, name).is_some();
    let ok_f = dom::add_false_to_object(&mut root, name).is_some();
    let ok_r = dom::add_raw_to_object(&mut root, name, Some(raw)).is_some();
    let ok_o = dom::add_object_to_object(&mut root, name).is_some();
    let ok_a = dom::add_array_to_object(&mut root, name).is_some();

    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "false={};bool={};raw=",
            dom::type_code(&fal),
            dom::type_code(&boo)
        )
        .as_bytes(),
    );
    push_bytes(&mut out, rw.as_ref().and_then(dom::value_string));
    out.extend_from_slice(b";ints=");
    push_num_array(&mut out, arr_i.as_ref());
    out.extend_from_slice(b";flts=");
    push_num_array(&mut out, arr_g.as_ref());
    out.extend_from_slice(b";dbls=");
    push_num_array(&mut out, arr_d.as_ref());
    out.extend_from_slice(b";strs=");
    push_str_array(&mut out, arr_s.as_ref());
    out.extend_from_slice(
        format!(
            ";addT={};addF={};addR={};addO={};addA={};obj=",
            i32::from(ok_t),
            i32::from(ok_f),
            i32::from(ok_r),
            i32::from(ok_o),
            i32::from(ok_a),
        )
        .as_bytes(),
    );
    match crate::print_value(&root, false) {
        Some(p) => out.extend_from_slice(&p),
        None => out.push(b'-'),
    }
    (0, out)
}

/// The driver's `<bits>` field: up to 16 hex digits, stopping at the first
/// character that is not one (a NUL included, since the C reads the field as a
/// C string). Missing digits read as 0.
///
/// The double arrives as raw IEEE-754 bits rather than decimal text for the same
/// reason [`encode_double`] emits bits: decimal would put `strtod` against
/// Rust's float parser on the compared contract, and it could not spell the
/// values this mode exists for — a NaN payload, a signalling NaN, `-0.0`. The
/// rule is hand-rolled on both sides so it is two lines shared, not two
/// libraries' notions of prefixes, whitespace and overflow.
fn parse_bits(field: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &b in field.iter().take(16) {
        let Some(d) = char::from(b).to_digit(16) else {
            break;
        };
        // `wrapping_shl`: the workspace denies arithmetic_side_effects, and 16
        // digits is exactly 64 bits, so nothing is discarded anyway.
        v = v.wrapping_shl(4) | u64::from(d);
    }
    v
}

/// One item as the C's `sb_item` spells it: the struct fields a C caller reads
/// straight off the pointer, then the printed form. `-` for a missing item.
///
/// `valuedouble` is in here deliberately. It is the field `cJSON_SetNumberHelper`
/// writes WITHOUT a type check, so a `cJSON_String` node can end up carrying a
/// number — a state the port cannot represent and refuses to create. That is an
/// intentional divergence, and a divergence has to be *visible* in the compared
/// bytes or its ledger entry is asserting something nothing measures
/// (LESSONS #31).
fn push_item(out: &mut Vec<u8>, item: Option<&Value>) {
    let Some(it) = item else {
        out.push(b'-');
        return;
    };
    out.extend_from_slice(
        format!(
            "t{},i{},d{:016x},s",
            dom::type_code(it),
            dom::value_int(it),
            dom::value_double(it).to_bits()
        )
        .as_bytes(),
    );
    push_bytes(out, dom::value_string(it));
    out.extend_from_slice(b",p");
    push_printed(out, Some(it));
}

/// `set`: stdin is `<bits>\t<key>\t<newstr>\n<json>` — both in-place setters
/// (`cJSON_SetValuestring`, `cJSON_SetNumberHelper`) in one shot.
///
/// Unlike `access`/`query`, an unparseable document is NOT an error: the setters
/// are the surface under test, so they still run and the descriptor reports
/// `doc=-`. That also keeps the fuzzer productive — a mode that exits 1 on most
/// mutations compares its error path over and over and its subject almost never.
///
/// This mode is what turned three of `MUTATION-API-SPIKE.md`'s hazards from
/// `read` rows into executed ones (LESSONS #38), and the first thing it executed
/// was a defect two readings of the same function had missed:
/// `cJSON_SetNumberHelper` performs no type check. Which is why the descriptor
/// carries the target's raw struct fields rather than only what an accessor
/// would report — a mode that only shows the tidy view finds only tidy bugs.
fn set_mode(input: &[u8]) -> (i32, Vec<u8>) {
    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
        return (RC_USAGE, Vec::new());
    };
    let (head, rest) = input.split_at(nl);
    let json = rest.get(1..).unwrap_or(&[]);
    let Some(t1) = head.iter().position(|&b| b == b'\t') else {
        return (RC_USAGE, Vec::new());
    };
    let (bits_field, after) = head.split_at(t1);
    let after = after.get(1..).unwrap_or(&[]);
    let Some(t2) = after.iter().position(|&b| b == b'\t') else {
        return (RC_USAGE, Vec::new());
    };
    let (key_field, new_field) = after.split_at(t2);
    let new_field = new_field.get(1..).unwrap_or(&[]);

    let num = f64::from_bits(parse_bits(bits_field));
    // Both fields reach the C as pointers into a NUL-split buffer, so both are
    // C strings before cJSON ever sees them.
    let key = cstr_prefix(key_field);
    let newstr = cstr_prefix(new_field);

    let mut root = crate::parse_with_length(json).ok().map(|(v, _)| v);

    // The document target, mutated then described. `sv`/`sn` are copied out of
    // the borrow so the document can be printed afterwards; in the C the same
    // two values are plain pointers into a tree nothing stops you mutating
    // again, which is the difference this port exists to make.
    let mut tgt = Vec::new();
    let mut sv: Option<Vec<u8>> = None;
    let mut sn: Option<f64> = None;
    match root
        .as_mut()
        .and_then(|r| dom::get_object_item_mut(r, key, true))
    {
        Some(t) => {
            sv = dom::set_valuestring(t, Some(newstr)).map(<[u8]>::to_vec);
            // Conditional on the target existing, because the C's
            // cJSON_SetNumberHelper has no NULL check at all — calling it with
            // one is a segfault in the oracle, and a segfault is not an answer
            // to compare against.
            sn = Some(dom::set_number(t, num));
            push_item(&mut tgt, Some(&*t));
        }
        // cJSON_SetValuestring's own `object == NULL` guard answers NULL here;
        // the port's `None` target reaches the same result by having nothing to
        // call it on.
        None => push_item(&mut tgt, None),
    }

    // A fresh string node whose OLD text is the key, so one input can land on
    // either side of the C's `strlen(new) <= strlen(old)` branch. Both sides of
    // it produce the same observable result — see `dom::set_valuestring`.
    let mut s2 = Value::String(key.to_vec());
    let sv2 = dom::set_valuestring(&mut s2, Some(newstr)).map(<[u8]>::to_vec);
    let svnull = dom::set_valuestring(&mut s2, None).map(<[u8]>::to_vec);

    // A NUMBER node: first the "not a string" guard, then the setter that owns
    // this node's type.
    let mut n2 = dom::number(0.0);
    let svnum = dom::set_valuestring(&mut n2, Some(newstr)).map(<[u8]>::to_vec);
    let sn2 = dom::set_number(&mut n2, num);

    let mut out = b"tgt=".to_vec();
    out.extend_from_slice(&tgt);
    out.extend_from_slice(b";sv=");
    push_bytes(&mut out, sv.as_deref());
    out.extend_from_slice(b";sn=");
    match sn {
        Some(d) => out.extend_from_slice(format!("{:016x}", d.to_bits()).as_bytes()),
        None => out.push(b'-'),
    }
    out.extend_from_slice(b";s2=");
    push_item(&mut out, Some(&s2));
    out.extend_from_slice(b";sv2=");
    push_bytes(&mut out, sv2.as_deref());
    out.extend_from_slice(b";svnull=");
    push_bytes(&mut out, svnull.as_deref());
    out.extend_from_slice(b";svnum=");
    push_bytes(&mut out, svnum.as_deref());
    out.extend_from_slice(b";n2=");
    push_item(&mut out, Some(&n2));
    out.extend_from_slice(format!(";sn2={:016x};doc=", sn2.to_bits()).as_bytes());
    match root.as_ref().and_then(|r| crate::print_value(r, false)) {
        Some(p) => out.extend_from_slice(&p),
        None => out.push(b'-'),
    }
    (0, out)
}

/// Everything up to the first NUL — the C driver hands `cjson_modes_construct`
/// pointers into a NUL-split buffer, so both fields are C strings.
fn cstr_prefix(s: &[u8]) -> &[u8] {
    s.get(..s.iter().position(|&b| b == 0).unwrap_or(s.len()))
        .unwrap_or(s)
}

/// Length-prefixed bytes, or `-` for NULL — the exact counterpart of the C
/// descriptors' `sb_bytes`. Length-prefixed rather than delimited because
/// `["a,b"]` and `["a","b"]` would otherwise render identically and a real
/// divergence between them would be invisible.
///
/// The bytes are C-STRING bytes: `sb_bytes` measures with `strlen` and writes
/// with `%s`, so both stop at the first NUL, and so does this (LESSONS #29 — the
/// truncation has to hold at every boundary). It makes no difference to
/// `construct`, whose values are already NUL-truncated at construction, but it
/// does to `set`, which can be handed a PARSED string with an interior NUL.
fn push_bytes(out: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(s) => {
            let s = &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())];
            out.extend_from_slice(format!("{}:", s.len()).as_bytes());
            out.extend_from_slice(s);
        }
        None => out.push(b'-'),
    }
}

/// A number array as the C descriptor spells it: `-` for NULL, else the size and
/// every element's `valueint` and `valuedouble` bits. `valueint` is the point —
/// the saturation in `dom::number` is the only computation these constructors do.
fn push_num_array(out: &mut Vec<u8>, arr: Option<&Value>) {
    let Some(Value::Array(items)) = arr else {
        out.push(b'-');
        return;
    };
    out.extend_from_slice(format!("{}", items.len()).as_bytes());
    for it in items {
        let d = match it {
            Value::Number(n) => n.d,
            _ => f64::NAN,
        };
        // Raw bits, NOT `encode_double`: this descriptor must distinguish NaN
        // payloads and the sign of -0.0, and `valuedouble` here comes straight
        // from the caller's bytes rather than from an accessor's NULL fallback.
        out.extend_from_slice(format!("|{},{:016x}", dom::value_int(it), d.to_bits()).as_bytes());
    }
}

fn push_str_array(out: &mut Vec<u8>, arr: Option<&Value>) {
    let Some(Value::Array(items)) = arr else {
        out.push(b'-');
        return;
    };
    out.extend_from_slice(format!("{}", items.len()).as_bytes());
    for it in items {
        out.push(b'|');
        push_bytes(out, dom::value_string(it));
    }
}

/// `cJSON_PrintUnformatted(item)` for the descriptor, or `-` for a NULL item.
fn push_printed(out: &mut Vec<u8>, item: Option<&Value>) {
    match item.and_then(|v| crate::print_value(v, false)) {
        Some(p) => out.extend_from_slice(&p),
        None => out.push(b'-'),
    }
}

/// `valuestring` as the C driver's `%s` renders it: NUL-truncated, `-` for NULL.
fn push_cstr(out: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        Some(s) => out.extend_from_slice(&s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())]),
        None => out.push(b'-'),
    }
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
        // Match the C driver's variant-name normalization EXACTLY: strip at most
        // ONE trailing '\n' (the C's `if (input[len-1]=='\n') input[--len]='\0'`),
        // then treat the name as a C string — `cjson_modes_build` compares it with
        // strcmp, which stops at the first NUL. NOT a general `trim_end()` (that
        // would also eat '\r'/space/tab and disagree with the C on a fuzzed name).
        let mut name = input;
        if name.last() == Some(&b'\n') {
            name = &name[..name.len().saturating_sub(1)];
        }
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let variant = String::from_utf8_lossy(&name[..end]);
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
    if mode == "access" {
        return access(input);
    }
    if mode == "construct" {
        return construct(input);
    }
    if mode == "set" {
        return set_mode(input);
    }

    // cJSON_Utils modes (JSON Pointer / Patch / Merge / Sort) — one dispatch,
    // so the differential driver and the probe glue reach the same code
    // (LESSONS #26). `-cs` selects the case-sensitive variant.
    let base = mode.strip_suffix("-cs").unwrap_or(mode);
    if matches!(
        base,
        "ptr" | "patch" | "merge" | "genmerge" | "genpatch" | "findptr" | "addpatch" | "sort"
    ) {
        return crate::utils::run(mode, input);
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
