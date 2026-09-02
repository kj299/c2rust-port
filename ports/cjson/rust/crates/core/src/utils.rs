//! `cJSON_Utils` ported to safe Rust: JSON Pointer (RFC 6901), JSON Patch
//! (RFC 6902), JSON Merge-Patch (RFC 7396), and object sorting.
//!
//! Ported probe-then-port from `c/cJSON_Utils.c`. The behavior here is the C's
//! *observed* behavior (LESSONS #17/#21) — including several quirks that would
//! be wrong to "clean up": `SortObject` is NON-recursive, sorting an array
//! permutes it via a NULL-key mergesort, the default sort is case-INsensitive,
//! and `test`/generate compare objects by SORTING them in place first.
//!
//! **One deliberate fix-of-defect (DIVERGENCES.md `utils-tilde-*`).**
//! The C's `decode_pointer_inplace` mis-decodes a `~0`/`~1` escape in a Patch
//! *child key*: `add /a~1b` builds the key `a~/` instead of `a/b` (it writes
//! `decoded_string[1]` where `[0]` is meant), and `remove`/`replace` of such a
//! key fail (status 13). A patch silently writing to the wrong key is a
//! correctness/authorization defect, so this port's `decode_pointer_inplace`
//! writes the escape correctly. It is otherwise a *faithful* simulation of the
//! C's in-place two-index decoder — an INVALID escape (`~` + junk, trailing `~`)
//! leaves the same partial/raw key the corrected reference does, not a clean
//! RFC decode — so only the `~0`/`~1` write is the divergence. JSON Pointer
//! *get* uses a separate, already-correct decoder (`decode_token`, mirroring the
//! C's `compare_pointers`). The divergence is ledgered and pinned by
//! `utils::tests`.

use crate::dom;
use crate::num::compare_double;
use crate::value::Value;

// ---- JSON Pointer (RFC 6901) -----------------------------------------------

/// Decode one reference token for the **GetPointer** path: `~1` → `/`, `~0` →
/// `~`. `None` on a trailing `~` or a `~` followed by anything but `0`/`1` — the
/// C's `compare_pointers` returns *false* on such a token, so the child never
/// matches and GetPointer resolves to nothing. The **Patch** path uses a
/// different decoder (`decode_pointer_inplace`) with different malformed-input
/// behavior; keep the two apart (see module header and LESSONS).
fn decode_token(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'~' {
            match raw.get(i.saturating_add(1)) {
                Some(b'0') => out.push(b'~'),
                Some(b'1') => out.push(b'/'),
                _ => return None,
            }
            i = i.saturating_add(2);
        } else {
            out.push(raw[i]);
            i = i.saturating_add(1);
        }
    }
    Some(out)
}

/// Faithful reproduction of the C `decode_array_index_from_pointer`, quirks and
/// all. The C reads a **C string** terminated by `'\0'` OR `'/'`, so the token
/// runs to the first `/`, first NUL, or the slice end (whichever comes first) —
/// NOT the whole slice. This matters for a Patch child key decoded from `~1`:
/// the decoded byte is `/`, which the C reads as an EMPTY digit run terminated
/// by `/`, i.e. index 0. Other quirks: a leading zero is rejected; the digit
/// loop's upper bound tests the *first* byte (`pointer[0] <= '9'`), so once the
/// first byte is a digit every following byte `>= '0'` (`:`, `;`, letters…) is
/// folded in with wrapping `size_t` arithmetic. `None` = not an index.
fn decode_array_index(tok: &[u8]) -> Option<usize> {
    // The C indexes a NUL-terminated buffer; model `pointer[i]` past the end as
    // the terminating NUL. Both `'\0'` (0) and `'/'` end the token.
    let byte_at = |i: usize| -> u8 { tok.get(i).copied().unwrap_or(0) };
    let first = byte_at(0);
    // leading zero not permitted unless the token IS "0" (next byte is a
    // terminator): the C tests `pointer[1] != '\0' && pointer[1] != '/'`.
    if first == b'0' && byte_at(1) != 0 && byte_at(1) != b'/' {
        return None;
    }
    let mut parsed: usize = 0;
    let mut pos = 0;
    while byte_at(pos) >= b'0' && first <= b'9' {
        parsed = parsed
            .wrapping_mul(10)
            .wrapping_add(usize::from(byte_at(pos).wrapping_sub(b'0')));
        pos = pos.saturating_add(1);
    }
    // the token must end at a terminator; any other byte -> not a valid index
    let end = byte_at(pos);
    if end != 0 && end != b'/' {
        return None;
    }
    Some(parsed)
}

/// Faithful simulation of the C `decode_pointer_inplace` — the decoder JSON
/// Patch uses for a CHILD KEY (distinct from GetPointer's `decode_token`, which
/// treats an invalid escape as no-match). This one decodes the CORRECT `~0`/`~1`
/// (the pristine C's `~1` write is the ledgered bug `utils-tilde-*`) but on an
/// invalid escape (trailing `~`, or `~` + junk) the C returns early, leaving the
/// rest of the buffer raw and un-terminated. That produces the exact mangled
/// keys the corrected reference does (`/a~1b~x` → key `a/bb~x`), so this mirrors
/// the two-index in-place mutation rather than decoding cleanly. The result is
/// truncated at the first NUL, as cJSON's C-string key would be.
fn decode_pointer_inplace(raw: &[u8]) -> Vec<u8> {
    let mut buf = raw.to_vec();
    let mut d = 0usize; // decoded write index
    let mut s = 0usize; // read index
    while s < buf.len() && buf[s] != 0 {
        if buf[s] == b'~' {
            match buf.get(s.saturating_add(1)).copied() {
                Some(b'0') => buf[d] = b'~',
                Some(b'1') => buf[d] = b'/',
                _ => return nul_trunc(&buf).to_vec(), // invalid: rest left raw
            }
            s = s.saturating_add(1);
        } else {
            buf[d] = buf[s];
        }
        d = d.saturating_add(1);
        s = s.saturating_add(1);
    }
    buf.truncate(d);
    buf
}

fn key_matches(entry_key: &[u8], token: &[u8], case_sensitive: bool) -> bool {
    // cJSON keys are C strings: `strcmp` / `case_insensitive_strcmp` (and
    // `compare_pointers`, which stops at the entry key's NUL) all compare only up
    // to the first NUL. Truncate both sides so a key like `a\0b` matches `a`,
    // exactly as the C does — and consistently with the base port, which already
    // NUL-truncates string values (dom::compare) and every printed key
    // (LESSONS #29: C-string semantics must hold at every key boundary, not most).
    let a = nul_trunc(entry_key);
    let b = nul_trunc(token);
    if case_sensitive {
        a == b
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

/// The index-path a pointer walks to, as a list of positions (object member
/// index or array index at each level). `None` if the pointer resolves to
/// nothing. Returning positions rather than a borrow keeps mutable navigation
/// (Patch) free of borrow-checker gymnastics.
fn locate(root: &Value, pointer: &[u8], case_sensitive: bool) -> Option<Vec<usize>> {
    let mut path = Vec::new();
    let mut cur = root;
    let mut p = pointer;
    while p.first() == Some(&b'/') {
        p = p.get(1..).unwrap_or(&[]);
        let end = p.iter().position(|&c| c == b'/').unwrap_or(p.len());
        let tok = &p[..end];
        match cur {
            Value::Array(items) => {
                let idx = decode_array_index(tok)?;
                cur = items.get(idx)?;
                path.push(idx);
            }
            Value::Object(entries) => {
                let decoded = decode_token(tok)?;
                let pos = entries
                    .iter()
                    .position(|(k, _)| key_matches(k, &decoded, case_sensitive))?;
                cur = &entries[pos].1;
                path.push(pos);
            }
            _ => return None,
        }
        p = &p[end..];
    }
    Some(path)
}

fn get_by_path<'a>(root: &'a Value, path: &[usize]) -> Option<&'a Value> {
    let mut cur = root;
    for &i in path {
        cur = match cur {
            Value::Array(items) => items.get(i)?,
            Value::Object(entries) => entries.get(i).map(|(_, v)| v)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn get_mut_by_path<'a>(root: &'a mut Value, path: &[usize]) -> Option<&'a mut Value> {
    let mut cur = root;
    for &i in path {
        cur = match cur {
            Value::Array(items) => items.get_mut(i)?,
            Value::Object(entries) => entries.get_mut(i).map(|(_, v)| v)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// `cJSONUtils_GetPointer` — the value a pointer resolves to.
#[must_use]
pub fn get_pointer<'a>(root: &'a Value, pointer: &[u8], case_sensitive: bool) -> Option<&'a Value> {
    let path = locate(root, pointer, case_sensitive)?;
    get_by_path(root, &path)
}

// ---- sorting (non-recursive; NULL-key mergesort for arrays) -----------------

/// C `compare_strings`: NULL keys are never equal (returns 1 here as a positive
/// "greater"), otherwise `strcmp`/case-insensitive compare. Arrays carry `None`
/// keys, which is how a NULL-key mergesort permutes them.
fn compare_keys(a: Option<&[u8]>, b: Option<&[u8]>, case_sensitive: bool) -> i32 {
    // Only the SIGN is ever consumed (`< 0`, `== 0`, `>= 0`), so returning
    // {-1,0,1} avoids the workspace's cast/overflow lints while matching every
    // decision the C's `compare_strings` magnitude drives.
    let ord = match (a, b) {
        (Some(x), Some(y)) => {
            // `compare_strings` uses strcmp/strcasecmp — both stop at the first
            // NUL — so order the NUL-truncated keys.
            let (x, y) = (nul_trunc(x), nul_trunc(y));
            if case_sensitive {
                x.cmp(y)
            } else {
                let lower =
                    |s: &[u8]| -> Vec<u8> { s.iter().map(u8::to_ascii_lowercase).collect() };
                lower(x).cmp(&lower(y))
            }
        }
        // a NULL key (array child) is never equal — the C returns positive 1
        _ => return 1,
    };
    match ord {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

type Entry = (Option<Vec<u8>>, Value);

/// Faithful port of the C `sort_list`: an already-strictly-ascending list is
/// returned untouched; otherwise split at `ceil(n/2)`, recurse, and merge
/// taking the SECOND list's element on a tie (`compare >= 0`) — which is what
/// reverses adjacent equal keys and permutes NULL-key arrays exactly as the C.
fn sort_list(mut list: Vec<Entry>, case_sensitive: bool) -> Vec<Entry> {
    let n = list.len();
    if n <= 1 {
        return list;
    }
    // already sorted (every adjacent pair strictly `<`)?
    let mut sorted = true;
    for i in 0..n.saturating_sub(1) {
        if compare_keys(
            list[i].0.as_deref(),
            list[i.saturating_add(1)].0.as_deref(),
            case_sensitive,
        ) >= 0
        {
            sorted = false;
            break;
        }
    }
    if sorted {
        return list;
    }
    let mid = n.div_ceil(2);
    let second = list.split_off(mid);
    let first = sort_list(list, case_sensitive);
    let second = sort_list(second, case_sensitive);
    let mut out = Vec::with_capacity(n);
    let (mut i, mut j) = (0, 0);
    while i < first.len() && j < second.len() {
        if compare_keys(
            first[i].0.as_deref(),
            second[j].0.as_deref(),
            case_sensitive,
        ) < 0
        {
            out.push(first[i].clone());
            i = i.saturating_add(1);
        } else {
            out.push(second[j].clone());
            j = j.saturating_add(1);
        }
    }
    out.extend_from_slice(&first[i..]);
    out.extend_from_slice(&second[j..]);
    out
}

/// `sort_object` — sort a node's IMMEDIATE children (non-recursive). An object
/// sorts by key; an array's children carry `None` keys and get permuted; any
/// other node is unchanged.
fn sort_children(v: &mut Value, case_sensitive: bool) {
    match v {
        Value::Object(entries) => {
            let taken: Vec<Entry> = core::mem::take(entries)
                .into_iter()
                .map(|(k, val)| (Some(k), val))
                .collect();
            *entries = sort_list(taken, case_sensitive)
                .into_iter()
                .map(|(k, val)| (k.unwrap_or_default(), val))
                .collect();
        }
        Value::Array(items) => {
            let taken: Vec<Entry> = core::mem::take(items)
                .into_iter()
                .map(|val| (None, val))
                .collect();
            *items = sort_list(taken, case_sensitive)
                .into_iter()
                .map(|(_, val)| val)
                .collect();
        }
        _ => {}
    }
}

/// `cJSONUtils_SortObject` / `...CaseSensitive`.
pub fn sort_object(v: &mut Value, case_sensitive: bool) {
    sort_children(v, case_sensitive);
}

// ---- compare_json (sorts objects in place, like the C) ---------------------

fn nul_trunc(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
}

/// C `compare_json`: mismatched top type → false; numbers compare int AND
/// double; strings compare bytes to the first NUL; arrays elementwise; objects
/// are SORTED IN PLACE then compared key-and-value in order. The in-place sort
/// is an observable side effect the `test`/generate paths rely on.
fn compare_json(a: &mut Value, b: &mut Value, cs: bool) -> bool {
    if dom::type_code(a) != dom::type_code(b) {
        return false;
    }
    match dom::type_code(a) {
        8 => match (&*a, &*b) {
            (Value::Number(na), Value::Number(nb)) => na.i == nb.i && compare_double(na.d, nb.d),
            _ => false,
        },
        16 => match (&*a, &*b) {
            (Value::String(sa), Value::String(sb)) => nul_trunc(sa) == nul_trunc(sb),
            _ => false,
        },
        32 => {
            let (ia, ib) = match (a, b) {
                (Value::Array(ia), Value::Array(ib)) => (ia, ib),
                _ => return false,
            };
            if ia.len() != ib.len() {
                return false;
            }
            ia.iter_mut()
                .zip(ib.iter_mut())
                .all(|(x, y)| compare_json(x, y, cs))
        }
        64 => {
            sort_children(a, cs);
            sort_children(b, cs);
            let (ea, eb) = match (a, b) {
                (Value::Object(ea), Value::Object(eb)) => (ea, eb),
                _ => return false,
            };
            if ea.len() != eb.len() {
                return false;
            }
            for ((ka, va), (kb, vb)) in ea.iter_mut().zip(eb.iter_mut()) {
                if compare_keys(Some(ka), Some(kb), cs) != 0 || !compare_json(va, vb, cs) {
                    return false;
                }
            }
            true
        }
        _ => true, // null / true / false / raw
    }
}

// ---- JSON Patch (RFC 6902) -------------------------------------------------

/// The outcome of applying a patch set: the RFC-6902 `status` and the document,
/// where `root == None` models the C's `cJSON_Invalid` root (an empty-path
/// `remove`), which the C printer renders as nothing / a NULL return.
pub struct PatchOutcome {
    pub status: i32,
    pub root: Option<Value>,
}

fn split_parent_child(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let slash = path.iter().rposition(|&c| c == b'/')?;
    Some((
        &path[..slash],
        path.get(slash.saturating_add(1)..).unwrap_or(&[]),
    ))
}

/// Detach the child named by `path`'s last segment; returns the removed value
/// and mutates `root`. `None` if the parent or child can't be found.
fn detach_path(root: &mut Value, path: &[u8], cs: bool) -> Option<Value> {
    let (parent_ptr, child_raw) = split_parent_child(path)?;
    // The C resolves the PARENT via get_item_from_pointer (GetPointer/
    // compare_pointers semantics, `decode_token`) but decodes the CHILD KEY with
    // the in-place decoder — a distinct code path that never fails (an invalid
    // escape yields a partial/raw key, not a no-match). Detach fails only when
    // the parent or the decoded child isn't found, so this is not fallible.
    let child = decode_pointer_inplace(child_raw);
    let parent_path = locate(root, parent_ptr, cs)?;
    let parent = get_mut_by_path(root, &parent_path)?;
    match parent {
        Value::Array(items) => {
            let idx = decode_array_index(&child)?;
            if idx < items.len() {
                Some(items.remove(idx))
            } else {
                None
            }
        }
        Value::Object(entries) => {
            let pos = entries
                .iter()
                .position(|(k, _)| key_matches(k, &child, cs))?;
            Some(entries.remove(pos).1)
        }
        _ => None,
    }
}

fn patch_op<'a>(patch: &'a Value, field: &[u8], cs: bool) -> Option<&'a Value> {
    dom::get_object_item(patch, field, cs)
}

/// A patch operation's string field (`op` / `path` / `from`) as the C sees it: a
/// C string. cJSON stores these as `valuestring` (char*) and drives them through
/// `strcmp`/`strrchr`/`strlen`, so they terminate at the first NUL. Truncate here
/// so `path:"\0"` reads as the empty (root) path and `path:"/a/-\0"` as `/a/-`,
/// matching the C — the LESSONS #29 C-string rule, on the patch-string boundary
/// the key-compare fix didn't reach (found by high-budget diff-fuzz on `patch`).
fn as_string(v: Option<&Value>) -> Option<&[u8]> {
    match v {
        Some(Value::String(s)) => Some(nul_trunc(s)),
        _ => None,
    }
}

/// Apply one patch object to `doc` in place; returns the RFC-6902 status.
/// `invalid_root` is set when an empty-path `remove` invalidates the root.
fn apply_one(doc: &mut Value, patch: &Value, cs: bool, invalid_root: &mut bool) -> i32 {
    let path = match as_string(patch_op(patch, b"path", cs)) {
        Some(p) => p.to_vec(),
        None => return 2, // malformed: no string "path"
    };
    let op = match as_string(patch_op(patch, b"op", cs)) {
        Some(o) => o,
        None => return 3, // INVALID
    };
    let opcode = op;

    if opcode == b"test" {
        // Compare get_pointer(path) with "value". compare_json SORTS both
        // subtrees in place (an observable side effect), so both need a mutable
        // borrow — the target lives in the doc, the value is cloned out.
        let Some(target_path) = locate(doc, &path, cs) else {
            return 1; // no target -> not equal
        };
        let mut want = match patch_op(patch, b"value", cs) {
            Some(v) => v.clone(),
            None => return 1,
        };
        let Some(target) = get_mut_by_path(doc, &target_path) else {
            return 1;
        };
        return i32::from(!compare_json(target, &mut want, cs));
    }
    if opcode != b"add"
        && opcode != b"remove"
        && opcode != b"replace"
        && opcode != b"move"
        && opcode != b"copy"
    {
        return 3; // INVALID
    }

    // special case: empty path replaces / removes the whole document
    if path.is_empty() {
        if opcode == b"remove" {
            *invalid_root = true;
            return 0;
        }
        if opcode == b"replace" || opcode == b"add" {
            let value = match patch_op(patch, b"value", cs) {
                Some(v) => v.clone(),
                None => return 7,
            };
            *doc = value;
            return 0;
        }
    }

    // remove / replace: detach the old item first
    if opcode == b"remove" || opcode == b"replace" {
        if detach_path(doc, &path, cs).is_none() {
            return 13;
        }
        if opcode == b"remove" {
            return 0;
        }
    }

    // decide the value to insert
    let value: Value = if opcode == b"move" || opcode == b"copy" {
        let from = match as_string(patch_op(patch, b"from", cs)) {
            Some(f) => f.to_vec(),
            None => return 4,
        };
        if opcode == b"move" {
            match detach_path(doc, &from, cs) {
                Some(v) => v,
                None => return 5,
            }
        } else {
            match get_pointer(doc, &from, cs) {
                Some(v) => v.clone(),
                None => return 5,
            }
        }
    } else {
        // add / replace use "value"
        match patch_op(patch, b"value", cs) {
            Some(v) => v.clone(),
            None => return 7,
        }
    };

    // split path into parent + child. The child key uses the Patch in-place
    // decoder: `~0`/`~1` decode CORRECTLY (the ledgered fix of the C's `~1`
    // mis-write) while an INVALID escape yields the same partial/raw key the
    // corrected C leaves — it never fails, so the only status-9 here is a missing
    // `/` (no parent) or an unresolvable parent, exactly as the C's `child_pointer
    // == NULL || parent == NULL` check.
    let Some((parent_ptr, child_raw)) = split_parent_child(&path) else {
        return 9;
    };
    let child = decode_pointer_inplace(child_raw);
    let Some(parent_path) = locate(doc, parent_ptr, cs) else {
        return 9;
    };
    let Some(parent) = get_mut_by_path(doc, &parent_path) else {
        return 9;
    };
    match parent {
        Value::Array(items) => {
            if child_raw == b"-" {
                items.push(value);
                0
            } else {
                let Some(idx) = decode_array_index(&child) else {
                    return 11;
                };
                if idx > items.len() {
                    return 10;
                }
                items.insert(idx, value);
                0
            }
        }
        Value::Object(entries) => {
            entries.retain(|(k, _)| !key_matches(k, &child, cs));
            entries.push((child, value));
            0
        }
        _ => 9,
    }
}

/// `cJSONUtils_ApplyPatches` — apply an array of patch objects in order,
/// stopping at the first nonzero status.
fn apply_patches(mut doc: Value, patches: &Value, cs: bool) -> PatchOutcome {
    let Value::Array(ops) = patches else {
        return PatchOutcome {
            status: 1,
            root: Some(doc),
        };
    };
    let mut invalid_root = false;
    for op in ops {
        let status = apply_one(&mut doc, op, cs, &mut invalid_root);
        if invalid_root {
            return PatchOutcome { status, root: None };
        }
        if status != 0 {
            return PatchOutcome {
                status,
                root: Some(doc),
            };
        }
    }
    PatchOutcome {
        status: 0,
        root: Some(doc),
    }
}

// ---- Merge-Patch (RFC 7396) ------------------------------------------------

/// `merge_patch`: apply `patch` to `target`, returning the merged tree. A
/// non-object patch replaces wholesale; a null member removes a key.
fn merge_patch(target: Option<Value>, patch: &Value, cs: bool) -> Value {
    let Value::Object(patch_members) = patch else {
        return patch.clone();
    };
    let mut obj = match target {
        Some(Value::Object(entries)) => entries,
        _ => Vec::new(),
    };
    for (key, pval) in patch_members {
        if matches!(pval, Value::Null) {
            // RFC 7396: null removes the key. The C calls
            // `cJSON_DeleteItemFromObject`, which deletes only the FIRST match
            // (its list walk stops at the first), so with duplicate keys a single
            // null-merge removes ONE, not all.
            if let Some(pos) = obj.iter().position(|(k, _)| key_matches(k, key, cs)) {
                obj.remove(pos);
            }
        } else {
            let existing = obj
                .iter()
                .position(|(k, _)| key_matches(k, key, cs))
                .map(|pos| obj.remove(pos).1);
            let replacement = merge_patch(existing, pval, cs);
            obj.push((key.clone(), replacement));
        }
    }
    Value::Object(obj)
}

// ---- Generate Merge-Patch --------------------------------------------------

/// Two cJSON quirks are faithful here, both found by high-budget diff-fuzz on
/// `genmerge`:
///   * the key DIFF is a hardcoded case-SENSITIVE `strcmp` (cJSON_Utils.c:1423),
///     independent of `cs` — so with the default (case-insensitive) genmerge the
///     children are SORTED case-insensitively but DIFFED case-sensitively, and
///     `{"a":1}` vs `{"A":2}` yields `{"A":2,"a":null}`, not a value change; and
///   * the recursion (cJSON_Utils.c:1455) calls the public *case-insensitive*
///     `cJSONUtils_GenerateMergePatch`, so a nested diff is ALWAYS case-
///     insensitive even under `...GenerateMergePatchCaseSensitive`.
fn generate_merge_patch(from: &mut Value, to: &mut Value, cs: bool) -> Option<Value> {
    if !matches!(to, Value::Object(_)) || !matches!(from, Value::Object(_)) {
        return Some(to.clone());
    }
    sort_children(from, cs);
    sort_children(to, cs);
    let (fe, te) = match (from, to) {
        (Value::Object(fe), Value::Object(te)) => (fe, te),
        _ => return None,
    };
    let mut patch: Vec<(Vec<u8>, Value)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < fe.len() || j < te.len() {
        let diff = if i < fe.len() {
            if j < te.len() {
                // hardcoded strcmp (case-sensitive), NOT `cs` — the C's line 1423.
                compare_keys(Some(&fe[i].0), Some(&te[j].0), true)
            } else {
                -1
            }
        } else {
            1
        };
        if diff < 0 {
            patch.push((fe[i].0.clone(), Value::Null));
            i = i.saturating_add(1);
        } else if diff > 0 {
            patch.push((te[j].0.clone(), te[j].1.clone()));
            j = j.saturating_add(1);
        } else {
            if !compare_json(&mut fe[i].1.clone(), &mut te[j].1.clone(), cs) {
                // the C recurses through the public case-INsensitive entry (:1455).
                if let Some(sub) =
                    generate_merge_patch(&mut fe[i].1.clone(), &mut te[j].1.clone(), false)
                {
                    patch.push((te[j].0.clone(), sub));
                }
            }
            i = i.saturating_add(1);
            j = j.saturating_add(1);
        }
    }
    if patch.is_empty() {
        None
    } else {
        Some(Value::Object(patch))
    }
}

// ---- Generate Patches (RFC 6902) -------------------------------------------

fn encode_pointer_segment(s: &[u8]) -> Vec<u8> {
    // The C's `encode_string_as_pointer` / `pointer_encoded_length` walk the key
    // as a C string (strlen-based), so a key `a\0b` encodes as `a` — truncate at
    // the first NUL before escaping (LESSONS #29). Without this the raw NUL rides
    // into the generated path and drops every following segment when it prints.
    let s = nul_trunc(s);
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        match c {
            b'/' => out.extend_from_slice(b"~1"),
            b'~' => out.extend_from_slice(b"~0"),
            _ => out.push(c),
        }
    }
    out
}

fn compose_patch(patches: &mut Vec<Value>, op: &[u8], path: &[u8], value: Option<&Value>) {
    let mut patch = vec![
        (b"op".to_vec(), Value::String(op.to_vec())),
        (b"path".to_vec(), Value::String(path.to_vec())),
    ];
    if let Some(v) = value {
        patch.push((b"value".to_vec(), v.clone()));
    }
    patches.push(Value::Object(patch));
}

fn create_patches(
    patches: &mut Vec<Value>,
    path: &[u8],
    from: &mut Value,
    to: &mut Value,
    cs: bool,
) {
    if dom::type_code(from) != dom::type_code(to) {
        compose_patch(patches, b"replace", path, Some(&to.clone()));
        return;
    }
    match dom::type_code(from) {
        8 => {
            let same = matches!((&*from, &*to), (Value::Number(a), Value::Number(b))
                if a.i == b.i && compare_double(a.d, b.d));
            if !same {
                compose_patch(patches, b"replace", path, Some(&to.clone()));
            }
        }
        16 => {
            let same = matches!((&*from, &*to), (Value::String(a), Value::String(b))
                if nul_trunc(a) == nul_trunc(b));
            if !same {
                compose_patch(patches, b"replace", path, Some(&to.clone()));
            }
        }
        32 => {
            let (fa, ta) = match (from, to) {
                (Value::Array(fa), Value::Array(ta)) => (fa, ta),
                _ => return,
            };
            let mut index = 0usize;
            while index < fa.len() && index < ta.len() {
                let seg = format!("{path}/{index}", path = String::from_utf8_lossy(path));
                create_patches(patches, seg.as_bytes(), &mut fa[index], &mut ta[index], cs);
                index = index.saturating_add(1);
            }
            // leftover in `from` -> remove; the C reuses the SAME index for every
            // leftover (the array shrinks under it), so `index` is fixed here
            let mut rm = index;
            while rm < fa.len() {
                let seg = format!(
                    "{path}/{index}",
                    path = String::from_utf8_lossy(path),
                    index = index
                );
                compose_patch(patches, b"remove", seg.as_bytes(), None);
                rm = rm.saturating_add(1);
            }
            // new in `to` -> add with the "-" (append) token
            let mut add = index;
            while add < ta.len() {
                let seg = format!("{}/-", String::from_utf8_lossy(path));
                compose_patch(patches, b"add", seg.as_bytes(), Some(&ta[add].clone()));
                add = add.saturating_add(1);
            }
        }
        64 => {
            sort_children(from, cs);
            sort_children(to, cs);
            let (fe, te) = match (from, to) {
                (Value::Object(fe), Value::Object(te)) => (fe, te),
                _ => return,
            };
            let (mut i, mut j) = (0, 0);
            while i < fe.len() || j < te.len() {
                let diff = if i >= fe.len() {
                    1
                } else if j >= te.len() {
                    -1
                } else {
                    compare_keys(Some(&fe[i].0), Some(&te[j].0), cs)
                };
                if diff == 0 {
                    let mut seg = path.to_vec();
                    seg.push(b'/');
                    seg.extend_from_slice(&encode_pointer_segment(&fe[i].0));
                    create_patches(
                        patches,
                        &seg,
                        &mut fe[i].1.clone(),
                        &mut te[j].1.clone(),
                        cs,
                    );
                    i = i.saturating_add(1);
                    j = j.saturating_add(1);
                } else if diff < 0 {
                    let mut seg = path.to_vec();
                    seg.push(b'/');
                    seg.extend_from_slice(&encode_pointer_segment(&fe[i].0));
                    compose_patch(patches, b"remove", &seg, None);
                    i = i.saturating_add(1);
                } else {
                    let mut seg = path.to_vec();
                    seg.push(b'/');
                    seg.extend_from_slice(&encode_pointer_segment(&te[j].0));
                    compose_patch(patches, b"add", &seg, Some(&te[j].1.clone()));
                    j = j.saturating_add(1);
                }
            }
        }
        _ => {}
    }
}

// ---- the rest of the public API (LESSONS #34) ------------------------------

/// `cJSONUtils_FindPointerFromObjectTo` — the pointer path from `root` down to
/// the node at `target_path`. The C walks the tree comparing NODE IDENTITY
/// (`object == target`) and returns `""` when the root *is* the target; since a
/// parsed document is a tree, each node has exactly one position, so walking the
/// located index-path yields the identical string. Array steps are the decimal
/// index (`%lu`), object steps the pointer-encoded key — the same encoder the C
/// uses, so `/a~1b` round-trips to `/a~1b`.
#[must_use]
pub fn find_pointer_from_object_to(root: &Value, target_path: &[usize]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = root;
    for &i in target_path {
        match cur {
            Value::Array(items) => {
                out.push(b'/');
                out.extend_from_slice(i.to_string().as_bytes());
                cur = items.get(i)?;
            }
            Value::Object(entries) => {
                let (k, v) = entries.get(i)?;
                out.push(b'/');
                out.extend_from_slice(&encode_pointer_segment(k));
                cur = v;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// `cJSONUtils_AddPatchToArray` — compose one `{op, path[, value]}` object onto
/// `patches`. The C is a one-line wrapper over the same `compose_patch` the
/// generate side uses, and so is this: `path` is stored verbatim (NOT re-encoded
/// — encoding is the caller's job), and `value` is deep-copied when present.
pub fn add_patch_to_array(patches: &mut Vec<Value>, op: &[u8], path: &[u8], value: Option<&Value>) {
    compose_patch(patches, op, path, value);
}

// ---- driver mode dispatch (the compared surface, LESSONS #26) --------------

fn print_or(v: &Value) -> Vec<u8> {
    crate::print_value(v, false).unwrap_or_default()
}

/// Run one utils driver mode with the two-document `<a>\n<b>` framing (or one
/// document for `sort`). Returns `(exit_code, stdout)` matching the C driver:
/// exit 1 with empty stdout on a parse failure or an invalidated root.
#[must_use]
pub fn run(mode: &str, input: &[u8]) -> (i32, Vec<u8>) {
    let cs = mode.ends_with("-cs");
    let base = mode.strip_suffix("-cs").unwrap_or(mode);

    if base == "sort" {
        let src = input.strip_suffix(b"\n").unwrap_or(input);
        let Ok((mut doc, _)) = crate::parse_with_length(src) else {
            return (1, Vec::new());
        };
        sort_object(&mut doc, cs);
        return (0, print_or(&doc));
    }

    // two-document modes split on the first newline. An unframed input (no
    // newline) reaches the C driver as a NULL result -> exit 1, so match that
    // rather than the usage code 2 (the differential compares exit codes).
    let Some(nl) = input.iter().position(|&b| b == b'\n') else {
        return (1, Vec::new());
    };
    let (a, rest) = input.split_at(nl);
    let b = rest.get(1..).unwrap_or(&[]);

    match base {
        "ptr" => {
            // a = pointer (a C string: `get_item_from_pointer` walks it byte by
            // byte and stops at the first NUL, so `/a\0/b` is the pointer `/a`),
            // b = json (parsed length-aware, NULs preserved). LESSONS #29.
            let Ok((doc, _)) = crate::parse_with_length(b) else {
                return (1, Vec::new());
            };
            match get_pointer(&doc, nul_trunc(a), cs) {
                Some(v) => (0, print_or(v)),
                None => (0, b"missing".to_vec()),
            }
        }
        "findptr" => {
            // a = pointer to the target (a C string), b = json. Resolve it the
            // way GetPointer does, then ask for the path back to that node.
            let Ok((doc, _)) = crate::parse_with_length(b) else {
                return (1, Vec::new());
            };
            match locate(&doc, nul_trunc(a), cs) {
                None => (0, b"missing".to_vec()),
                Some(path) => match find_pointer_from_object_to(&doc, &path) {
                    Some(p) => (0, p),
                    None => (0, b"null".to_vec()),
                },
            }
        }
        "addpatch" => {
            // a = "<op>\t<path>" (both C strings), b = optional value JSON.
            let a = nul_trunc(a);
            let Some(tab) = a.iter().position(|&c| c == b'\t') else {
                return (1, Vec::new()); // the C shim returns NULL -> exit 1
            };
            let (op, rest) = a.split_at(tab);
            let path = rest.get(1..).unwrap_or(&[]);
            let value = if b.is_empty() {
                None
            } else {
                match crate::parse_with_length(b) {
                    Ok((v, _)) => Some(v),
                    Err(_) => return (1, Vec::new()),
                }
            };
            let mut patches = Vec::new();
            add_patch_to_array(&mut patches, op, path, value.as_ref());
            (0, print_or(&Value::Array(patches)))
        }
        "patch" => {
            let (Ok((patches, _)), Ok((doc, _))) =
                (crate::parse_with_length(a), crate::parse_with_length(b))
            else {
                return (1, Vec::new());
            };
            let out = apply_patches(doc, &patches, cs);
            match out.root {
                None => (1, Vec::new()), // invalidated root -> C prints nothing
                Some(root) => {
                    let mut s = format!("status={};", out.status).into_bytes();
                    s.extend_from_slice(&print_or(&root));
                    (0, s)
                }
            }
        }
        "merge" => {
            // a = patch, b = target
            let (Ok((patch, _)), Ok((target, _))) =
                (crate::parse_with_length(a), crate::parse_with_length(b))
            else {
                return (1, Vec::new());
            };
            (0, print_or(&merge_patch(Some(target), &patch, cs)))
        }
        "genmerge" => {
            let (Ok((mut from, _)), Ok((mut to, _))) =
                (crate::parse_with_length(a), crate::parse_with_length(b))
            else {
                return (1, Vec::new());
            };
            match generate_merge_patch(&mut from, &mut to, cs) {
                Some(p) => (0, print_or(&p)),
                None => (0, b"null".to_vec()),
            }
        }
        "genpatch" => {
            let (Ok((mut from, _)), Ok((mut to, _))) =
                (crate::parse_with_length(a), crate::parse_with_length(b))
            else {
                return (1, Vec::new());
            };
            let mut patches = Vec::new();
            create_patches(&mut patches, b"", &mut from, &mut to, cs);
            (0, print_or(&Value::Array(patches)))
        }
        _ => (2, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_with_length;

    fn run_ok(mode: &str, input: &str) -> String {
        let (rc, out) = run(mode, input.as_bytes());
        assert_eq!(rc, 0, "mode {mode} exited {rc}");
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn pointer_resolves_and_escapes() {
        assert_eq!(run_ok("ptr", "/a/1\n{\"a\":[10,20]}"), "20");
        // GetPointer decodes ~1 correctly, matching the C
        assert_eq!(run_ok("ptr", "/a~1b\n{\"a/b\":9}"), "9");
    }

    #[test]
    fn sort_is_non_recursive_and_case_insensitive() {
        assert_eq!(
            run_ok("sort", "{\"b\":1,\"a\":{\"z\":1,\"y\":2}}"),
            "{\"a\":{\"z\":1,\"y\":2},\"b\":1}"
        );
        assert_eq!(run_ok("sort", "{\"B\":1,\"a\":2}"), "{\"a\":2,\"B\":1}");
    }

    // DIVERGENCE utils-patch-tilde-decode: the C mis-decodes a ~0/~1 escape in a
    // Patch child key (add /a~1b -> key "a~/"); this port decodes it correctly.
    #[test]
    fn patch_tilde_decode_is_fixed_not_faithful() {
        // correct: /a~1b targets the key "a/b"
        assert_eq!(
            run_ok(
                "patch",
                "[{\"op\":\"add\",\"path\":\"/a~1b\",\"value\":42}]\n{}"
            ),
            "status=0;{\"a/b\":42}"
        );
        // and remove of an escaped key now SUCCEEDS (C returned status 13)
        assert_eq!(
            run_ok(
                "patch",
                "[{\"op\":\"remove\",\"path\":\"/a~1b\"}]\n{\"a/b\":1,\"x\":2}"
            ),
            "status=0;{\"x\":2}"
        );
    }

    // An INVALID escape in a Patch child key is NOT a clean RFC decode: the C's
    // `decode_pointer_inplace` returns early leaving the partial/raw key. The
    // port reproduces that faithfully (only the `~0`/`~1` write is the ledgered
    // fix) — found by fuzzing `patch` against the corrected oracle.
    #[test]
    fn patch_invalid_escape_key_matches_corrected_c() {
        assert_eq!(
            run_ok(
                "patch",
                "[{\"op\":\"add\",\"path\":\"/~x\",\"value\":1}]\n{}"
            ),
            "status=0;{\"~x\":1}"
        );
        // a valid escape then an invalid one: `/a~1b~x` -> key `a/bb~x`
        assert_eq!(
            run_ok(
                "patch",
                "[{\"op\":\"add\",\"path\":\"/a~1b~x\",\"value\":1}]\n{}"
            ),
            "status=0;{\"a/bb~x\":1}"
        );
    }

    // `decode_array_index` reads a C string ending at '\0' OR '/', so a Patch
    // child key decoded from `~1` (-> `/`) is an empty digit run terminated by
    // '/', i.e. index 0. `/~1` into an array inserts at the front.
    #[test]
    fn patch_array_index_stops_at_slash() {
        assert_eq!(
            run_ok(
                "patch",
                "[{\"op\":\"add\",\"path\":\"/~1\",\"value\":9}]\n[0,1,2]"
            ),
            "status=0;[9,0,1,2]"
        );
    }

    // LESSONS #29: object keys compare as C strings — a key with an embedded NUL
    // matches its truncation, in merge/patch just as in dom lookup. `{"a\0":..}`
    // and `{"a":..}` are the same key.
    #[test]
    fn keys_compare_nul_truncated() {
        // merge patch key "a\0" replaces target key "a"
        let (rc, out) = run("merge", b"{\"a\x00\":1}\n{\"a\":3}");
        assert_eq!(
            (rc, String::from_utf8_lossy(&out).into_owned()),
            (0, "{\"a\":1}".into())
        );
    }

    // LESSONS #29 on the patch-string boundary: op/path/from are C strings, so a
    // NUL truncates them. `path:"\0"` is the empty (root) path; `/a/-\0` is `/a/-`
    // (array append). Found by high-budget diff-fuzz on `patch`.
    #[test]
    fn patch_path_is_nul_truncated() {
        // path "\0" == empty path: replace with no "value" is status 7 (not 13)
        let (rc, out) = run("patch", b"[{\"op\":\"replace\",\"path\":\"\x00\"}]\n\"\"");
        assert_eq!(
            (rc, String::from_utf8_lossy(&out).into_owned()),
            (0, "status=7;\"\"".into())
        );
        // path "/a/-\0" == "/a/-": append to the array
        let (rc, out) = run(
            "patch",
            b"[{\"op\":\"add\",\"path\":\"/a/-\x00\",\"value\":9}]\n{\"a\":[]}",
        );
        assert_eq!(
            (rc, String::from_utf8_lossy(&out).into_owned()),
            (0, "status=0;{\"a\":[9]}".into())
        );
    }

    // LESSONS #29 on the GetPointer boundary: the pointer is a C string, so
    // `/a\0/b` is the pointer `/a` — `get_item_from_pointer` stops at the NUL.
    #[test]
    fn pointer_is_nul_truncated() {
        assert_eq!(run_ok("ptr", "/a\u{0}/b\n{\"a\":1}"), "1");
        assert_eq!(run_ok("ptr", "/x\u{0}/y\n{\"x\":{\"y\":2}}"), "{\"y\":2}");
    }

    // generate_merge_patch DIFFS keys with a hardcoded case-sensitive strcmp
    // (cJSON_Utils.c:1423) even under the case-INsensitive default: `a` and `A`
    // are distinct, so `{"a":1}` -> `{"A":2}` is delete-a + add-A, not a change.
    #[test]
    fn genmerge_diffs_keys_case_sensitively() {
        assert_eq!(
            run_ok("genmerge", "{\"a\":1}\n{\"A\":2,\"\":3}"),
            "{\"\":3,\"A\":2,\"a\":null}"
        );
    }

    // LESSONS #29 on the generated-path boundary: encode_string_as_pointer is
    // strlen-based, so a key `a\0` encodes to `a` — a nested diff then addresses
    // `/a/`, not `/a` (the raw NUL would otherwise drop the tail on print).
    #[test]
    fn genpatch_encodes_nul_truncated_key_paths() {
        let (rc, out) = run("genpatch", b"{\"a\x00\":{\"\":3}}\n{\"a\":{\"\":2}}");
        assert_eq!(
            (rc, String::from_utf8_lossy(&out).into_owned()),
            (
                0,
                "[{\"op\":\"replace\",\"path\":\"/a/\",\"value\":2}]".into()
            )
        );
    }

    // The C's RFC-7396 null-merge calls cJSON_DeleteItemFromObject, which removes
    // only the FIRST matching key; a `retain` that removed all duplicates was a
    // fuzz-found divergence.
    #[test]
    fn merge_null_removes_only_the_first_duplicate() {
        assert_eq!(
            run_ok("merge", "{\"a\":null}\n{\"a\":1,\"a\":1,\"c\":6}"),
            "{\"a\":1,\"c\":6}"
        );
    }

    #[test]
    fn patch_test_sorts_the_compared_subtree() {
        // the C's compare_json sorts objects in place; a passing test re-sorts
        assert_eq!(
            run_ok(
                "patch",
                "[{\"op\":\"test\",\"path\":\"\",\"value\":{\"a\":1,\"b\":2}}]\n{\"b\":2,\"a\":1}"
            ),
            "status=0;{\"a\":1,\"b\":2}"
        );
    }

    #[test]
    fn invalidated_root_prints_nothing() {
        let (rc, out) = run("patch", b"[{\"op\":\"remove\",\"path\":\"\"}]\n{\"x\":1}");
        assert_eq!((rc, out.as_slice()), (1, &b""[..]));
    }

    #[test]
    fn parse_failures_are_rc1() {
        assert_eq!(run("ptr", b"/a\n{bad").0, 1);
        assert_eq!(run("merge", b"{bad\n{}").0, 1);
    }

    #[test]
    fn merge_removes_and_recurses() {
        assert_eq!(
            run_ok("merge", "{\"a\":null}\n{\"a\":1,\"b\":2}"),
            "{\"b\":2}"
        );
        // sanity: the parse helper is the shared core parser
        assert!(parse_with_length(b"{}").is_ok());
    }
}
