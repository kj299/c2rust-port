//! `cjson_rs` — the C-ABI surface over the `#![forbid(unsafe_code)]` core, the
//! port's ONLY crate with `unsafe`. It is the audited `extern "C"` shim: every
//! block validates the raw pointers/lengths the C caller supplies and then hands
//! off to the safe core, so all the memory-safety risk is confined here where
//! `audit_unsafe.py` enforces a `// SAFETY:` on every block.
//!
//! Scope (honest): the parse / serialize / minify / compare / duplicate pipeline
//! as real `cJSON_*` symbols over an OPAQUE handle (`Box<Value>`), plus the
//! single-shot shims `cjson_rt`/`cjson_rt_fmt` that let `lib_diff` drive the
//! whole parse→print pipeline in one call and compare it against the C `.so`.
//! The struct-field-access ABI (a caller reading `item->valueint` directly) and
//! the full `Add*`/`Get*` builder surface over FFI are the documented remainder
//! — most consumers use the accessor functions, which can be added as needed.

use cjson_core::{dom, minify as core_minify, parse_with_length, print_value, Value};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

/// Opaque handle = a leaked `Box<Value>`. The C sees `cJSON *`; we see this.
type Handle = *mut Value;

/// Read a NUL-terminated C string's bytes (borrowed), or None if null.
///
/// # Safety
/// `s` must be null or a valid pointer to a NUL-terminated C string that stays
/// valid for the duration of the call.
unsafe fn cstr_bytes<'a>(s: *const c_char) -> Option<&'a [u8]> {
    if s.is_null() {
        return None;
    }
    // SAFETY: caller guarantees `s` is a valid NUL-terminated C string (contract
    // above); CStr walks to the terminator without writing.
    Some(unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// cJSON.c `cJSON_Version` — a static version string.
#[no_mangle]
pub extern "C" fn cJSON_Version() -> *const c_char {
    // matches the C's CJSON_VERSION_* (cJSON.h): "1.7.18"
    b"1.7.18\0".as_ptr().cast::<c_char>()
}

/// cJSON.c:1104 `cJSON_ParseWithLength`. Returns an opaque handle, or NULL.
///
/// # Safety
/// `value` must be null or valid for reads of `buffer_length` bytes.
#[no_mangle]
pub unsafe extern "C" fn cJSON_ParseWithLength(
    value: *const c_char,
    buffer_length: usize,
) -> Handle {
    if value.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: caller guarantees `value` is valid for `buffer_length` bytes; we
    // only read them. The slice does not outlive this call.
    let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), buffer_length) };
    match parse_with_length(bytes) {
        Ok((v, _)) => Box::into_raw(Box::new(v)),
        Err(_) => ptr::null_mut(),
    }
}

/// cJSON.c `cJSON_Parse` — like `ParseWithLength` using `strlen(value)`.
///
/// # Safety
/// `value` must be null or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn cJSON_Parse(value: *const c_char) -> Handle {
    // SAFETY: forwarded contract; cstr_bytes validates null + walks to NUL.
    match unsafe { cstr_bytes(value) } {
        Some(bytes) => match parse_with_length(bytes) {
            Ok((v, _)) => Box::into_raw(Box::new(v)),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Print helper → a malloc-free-by-`cJSON_free` C string, or NULL.
fn print_to_cstring(item: Handle, formatted: bool) -> *mut c_char {
    if item.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `item` is a handle we minted with Box::into_raw and have not freed;
    // the caller must not pass a foreign or already-deleted pointer (the same
    // precondition the C has for a `cJSON *`). We only borrow it.
    let value: &Value = unsafe { &*item };
    match print_value(value, formatted) {
        // printed JSON never contains an interior NUL, so CString::new succeeds
        Some(bytes) => match CString::new(bytes) {
            Ok(cs) => cs.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// cJSON.c `cJSON_PrintUnformatted`. Result must be freed with `cJSON_free`.
///
/// # Safety
/// `item` must be a handle returned by this library and not yet deleted.
#[no_mangle]
pub unsafe extern "C" fn cJSON_PrintUnformatted(item: Handle) -> *mut c_char {
    print_to_cstring(item, false)
}

/// cJSON.c `cJSON_Print` (formatted). Result must be freed with `cJSON_free`.
///
/// # Safety
/// `item` must be a handle returned by this library and not yet deleted.
#[no_mangle]
pub unsafe extern "C" fn cJSON_Print(item: Handle) -> *mut c_char {
    print_to_cstring(item, true)
}

/// cJSON.c `cJSON_Delete` — drop the tree (Rust's drop = the recursive free).
///
/// # Safety
/// `item` must be null or a handle returned by this library, not yet deleted.
#[no_mangle]
pub unsafe extern "C" fn cJSON_Delete(item: Handle) {
    if !item.is_null() {
        // SAFETY: `item` was minted by Box::into_raw here and not previously
        // freed (caller contract); reclaim the Box so it drops.
        drop(unsafe { Box::from_raw(item) });
    }
}

/// cJSON.c `cJSON_free` — free a string returned by `cJSON_Print*`.
///
/// # Safety
/// `ptr` must be null or a pointer returned by `cJSON_Print`/`PrintUnformatted`
/// from THIS library, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn cJSON_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        // SAFETY: `ptr` came from CString::into_raw in this library (caller
        // contract); reclaim it so the CString drops with the right allocator.
        drop(unsafe { CString::from_raw(ptr.cast::<c_char>()) });
    }
}

/// cJSON.c `cJSON_Compare`.
///
/// # Safety
/// `a` and `b` must be null or handles returned by this library.
#[no_mangle]
pub unsafe extern "C" fn cJSON_Compare(a: Handle, b: Handle, case_sensitive: c_int) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    // SAFETY: both are live handles per the caller contract; borrowed only.
    let (av, bv) = unsafe { (&*a, &*b) };
    c_int::from(dom::compare(av, bv, case_sensitive != 0))
}

/// cJSON.c `cJSON_Duplicate` (recurse ignored — always a deep clone, as the
/// pipeline uses it).
///
/// # Safety
/// `item` must be null or a handle returned by this library.
#[no_mangle]
pub unsafe extern "C" fn cJSON_Duplicate(item: Handle, _recurse: c_int) -> Handle {
    if item.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: live handle per contract; borrowed only.
    let v: &Value = unsafe { &*item };
    Box::into_raw(Box::new(dom::duplicate(v)))
}

/// cJSON.c `cJSON_Minify` — minify a NUL-terminated buffer IN PLACE. The result
/// is always no longer than the input, so it fits (the C relies on the same).
///
/// # Safety
/// `json` must be null or a valid, writable, NUL-terminated C string buffer.
#[no_mangle]
pub unsafe extern "C" fn cJSON_Minify(json: *mut c_char) {
    if json.is_null() {
        return;
    }
    // SAFETY: caller guarantees a valid NUL-terminated writable buffer. We read
    // its bytes up to the NUL, compute the minified form (<= input length), and
    // write it back over the same buffer followed by a NUL — never past the
    // original length.
    let bytes = unsafe { CStr::from_ptr(json) }.to_bytes();
    let out = core_minify(bytes);
    let n = out.len(); // guaranteed <= bytes.len()
                       // SAFETY: `n <= bytes.len()`, and the buffer had room for `bytes.len()` + the
                       // NUL, so writing `n` bytes + a NUL stays in bounds.
    unsafe {
        ptr::copy_nonoverlapping(out.as_ptr(), json.cast::<u8>(), n);
        *json.add(n) = 0;
    }
}

// ---- single-shot shims for lib_diff (drive the whole pipeline in one call) --

/// Parse `json` and print it (unformatted) into `out` (capacity `out_size`,
/// always NUL-terminated). Returns the full printed length (may exceed the
/// buffer, snprintf-style), or -1 on parse failure. `fmt != 0` → formatted.
///
/// # Safety
/// `json` is a valid NUL-terminated C string; `out` is valid for writes of
/// `out_size` bytes.
unsafe fn roundtrip(json: *const c_char, out: *mut c_char, out_size: c_int, fmt: bool) -> c_int {
    // SAFETY: forwarded contracts.
    let Some(bytes) = (unsafe { cstr_bytes(json) }) else {
        return -1;
    };
    let value = match parse_with_length(bytes) {
        Ok((v, _)) => v,
        Err(_) => return -1,
    };
    let Some(printed) = print_value(&value, fmt) else {
        return -1;
    };
    let cap = out_size.max(0) as usize;
    if cap > 0 && !out.is_null() {
        let copy = printed.len().min(cap.saturating_sub(1));
        // SAFETY: `out` is valid for `out_size` bytes (caller); `copy < cap`, so
        // `copy` bytes + a NUL fit.
        unsafe {
            ptr::copy_nonoverlapping(printed.as_ptr(), out.cast::<u8>(), copy);
            *out.add(copy) = 0;
        }
    }
    c_int::try_from(printed.len()).unwrap_or(c_int::MAX)
}

/// # Safety
/// See `roundtrip`.
#[no_mangle]
pub unsafe extern "C" fn cjson_rt(json: *const c_char, out: *mut c_char, out_size: c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { roundtrip(json, out, out_size, false) }
}

/// # Safety
/// See `roundtrip`.
#[no_mangle]
pub unsafe extern "C" fn cjson_rt_fmt(
    json: *const c_char,
    out: *mut c_char,
    out_size: c_int,
) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { roundtrip(json, out, out_size, true) }
}

/// Copy `bytes` into `out` (capacity `out_size`, always NUL-terminated) and
/// return the FULL length, snprintf-style, so truncation is observable.
///
/// # Safety
/// `out` is valid for writes of `out_size` bytes, or null.
unsafe fn emit_bytes(bytes: &[u8], out: *mut c_char, out_size: c_int) -> c_int {
    let cap = out_size.max(0) as usize;
    if cap > 0 && !out.is_null() {
        let copy = bytes.len().min(cap.saturating_sub(1));
        // SAFETY: `out` is valid for `out_size` bytes (caller); `copy < cap`, so
        // `copy` bytes plus the NUL fit inside the buffer.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), copy);
            *out.add(copy) = 0;
        }
    }
    c_int::try_from(bytes.len()).unwrap_or(c_int::MAX)
}

/// Build the named document with the DOM builder API and print it unformatted
/// into `out`. Returns the printed length, or -1 for an unknown variant.
///
/// # Safety
/// `variant` is a valid NUL-terminated C string; `out` is valid for writes of
/// `out_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn cjson_build_variant(
    variant: *const c_char,
    out: *mut c_char,
    out_size: c_int,
) -> c_int {
    // SAFETY: forwarded contract.
    let Some(bytes) = (unsafe { cstr_bytes(variant) }) else {
        return -1;
    };
    let Ok(name) = core::str::from_utf8(bytes) else {
        return -1;
    };
    let Some(root) = cjson_core::modes::build_variant(name) else {
        return -1;
    };
    let Some(printed) = print_value(&root, false) else {
        return -1;
    };
    // SAFETY: forwarded contract on `out`/`out_size`.
    unsafe { emit_bytes(&printed, out, out_size) }
}

/// Look `key` up in `json` and write the canonical description (Is* predicates
/// plus the `type`/`valueint`/`valuestring` struct-field views) into `out`.
/// Returns the description length, or -1 if the document does not parse.
///
/// # Safety
/// `key` and `json` are valid NUL-terminated C strings; `out` is valid for
/// writes of `out_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn cjson_query_desc(
    key: *const c_char,
    json: *const c_char,
    out: *mut c_char,
    out_size: c_int,
) -> c_int {
    // SAFETY: forwarded contract on `key`.
    let Some(key_bytes) = (unsafe { cstr_bytes(key) }) else {
        return -1;
    };
    // SAFETY: forwarded contract on `json`.
    let Some(json_bytes) = (unsafe { cstr_bytes(json) }) else {
        return -1;
    };
    // `modes::run` takes the driver's `<key>\n<json>` framing.
    let mut input = key_bytes.to_vec();
    input.push(b'\n');
    input.extend_from_slice(json_bytes);
    let (rc, desc) = cjson_core::modes::run("query", &input);
    if rc != 0 {
        return -1;
    }
    // SAFETY: forwarded contract on `out`/`out_size`.
    unsafe { emit_bytes(&desc, out, out_size) }
}

#[cfg(test)]
mod tests {
    //! These tests exist to give MIRI something to check. The unsafe in this
    //! crate is the port's entire memory-safety risk surface, and `cargo miri
    //! test -p cjson_ffi` over a crate with NO tests is a vacuous pass — a gate
    //! that inspects nothing (LESSONS #6). Each test drives a real C-ABI call
    //! sequence the way a C consumer would, so miri validates the pointer
    //! provenance, the Box/CString round-trips, and the in-place minify writes.
    use super::*;

    fn c(s: &str) -> CString {
        CString::new(s).expect("no interior NUL in test input")
    }

    #[test]
    fn parse_print_free_roundtrip() {
        let json = c(r#"{"a":1,"b":[true,null,"x"]}"#);
        // SAFETY: `json` is a live NUL-terminated CString for the whole call.
        let item = unsafe { cJSON_Parse(json.as_ptr()) };
        assert!(!item.is_null());
        // SAFETY: `item` is a live handle from cJSON_Parse above.
        let printed = unsafe { cJSON_PrintUnformatted(item) };
        assert!(!printed.is_null());
        // SAFETY: `printed` is a live CString pointer from PrintUnformatted.
        let out = unsafe { CStr::from_ptr(printed) }.to_bytes().to_vec();
        assert_eq!(out, br#"{"a":1,"b":[true,null,"x"]}"#);
        // SAFETY: both pointers are live and freed exactly once here.
        unsafe {
            cJSON_free(printed.cast::<c_void>());
            cJSON_Delete(item);
        }
    }

    #[test]
    fn parse_with_length_respects_the_bound() {
        // The buffer is NOT NUL-terminated at the length we pass — the C-ABI
        // contract is length-bounded, and miri catches any read past it.
        let raw = b"[1,2,3]xxxxx";
        // SAFETY: `raw` is valid for reads of 7 bytes (we pass exactly 7).
        let item = unsafe { cJSON_ParseWithLength(raw.as_ptr().cast::<c_char>(), 7) };
        assert!(!item.is_null());
        // SAFETY: live handle.
        let printed = unsafe { cJSON_PrintUnformatted(item) };
        // SAFETY: live CString pointer.
        assert_eq!(unsafe { CStr::from_ptr(printed) }.to_bytes(), b"[1,2,3]");
        // SAFETY: each freed once.
        unsafe {
            cJSON_free(printed.cast::<c_void>());
            cJSON_Delete(item);
        }
    }

    #[test]
    fn duplicate_and_compare() {
        let json = c(r#"{"k":[1,2,{"n":true}]}"#);
        // SAFETY: live CString.
        let a = unsafe { cJSON_Parse(json.as_ptr()) };
        // SAFETY: live handle.
        let b = unsafe { cJSON_Duplicate(a, 1) };
        assert!(!b.is_null());
        // SAFETY: both live handles.
        assert_eq!(unsafe { cJSON_Compare(a, b, 1) }, 1);
        // SAFETY: freed once each.
        unsafe {
            cJSON_Delete(b);
            cJSON_Delete(a);
        }
    }

    #[test]
    fn minify_in_place_stays_in_bounds() {
        // A mutable NUL-terminated buffer, exactly what a C caller passes.
        let mut buf: Vec<c_char> = b"{ \"a\" : 1 , \"b\" : [ 2 , 3 ] }\0"
            .iter()
            .map(|&x| x as c_char)
            .collect();
        let cap = buf.len();
        // SAFETY: `buf` is a live, writable, NUL-terminated buffer.
        unsafe { cJSON_Minify(buf.as_mut_ptr()) };
        // SAFETY: still NUL-terminated after minify.
        let got = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes().to_vec();
        assert_eq!(got, br#"{"a":1,"b":[2,3]}"#);
        assert_eq!(
            buf.len(),
            cap,
            "minify must not reallocate the caller buffer"
        );
    }

    #[test]
    fn null_and_invalid_inputs_are_safe() {
        // SAFETY: passing null is explicitly allowed by every contract here.
        unsafe {
            assert!(cJSON_Parse(ptr::null()).is_null());
            assert!(cJSON_ParseWithLength(ptr::null(), 10).is_null());
            assert!(cJSON_Print(ptr::null_mut()).is_null());
            assert_eq!(cJSON_Compare(ptr::null_mut(), ptr::null_mut(), 1), 0);
            assert!(cJSON_Duplicate(ptr::null_mut(), 1).is_null());
            cJSON_Delete(ptr::null_mut()); // no-op
            cJSON_free(ptr::null_mut()); // no-op
            cJSON_Minify(ptr::null_mut()); // no-op
        }
        let bad = c("{not json");
        // SAFETY: live CString; a parse failure must return null, not UB.
        assert!(unsafe { cJSON_Parse(bad.as_ptr()) }.is_null());
    }

    #[test]
    fn version_is_the_c_version() {
        // SAFETY: cJSON_Version returns a 'static NUL-terminated literal.
        let v = unsafe { CStr::from_ptr(cJSON_Version()) };
        assert_eq!(v.to_bytes(), b"1.7.18");
    }

    #[test]
    fn roundtrip_shim_truncates_like_snprintf() {
        let json = c("[1,2,3,4,5]");
        let mut out = [0 as c_char; 6];
        // SAFETY: live CString in; `out` is valid for 6 writes.
        let n = unsafe { cjson_rt(json.as_ptr(), out.as_mut_ptr(), 6) };
        assert_eq!(n, 11, "returns the FULL length, snprintf-style");
        // SAFETY: `out` is NUL-terminated by the shim.
        assert_eq!(unsafe { CStr::from_ptr(out.as_ptr()) }.to_bytes(), b"[1,2,");
    }
}
