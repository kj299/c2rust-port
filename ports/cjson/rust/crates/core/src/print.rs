//! Modules 4/5, print side: `print_value` / `print_array` / `print_object` and
//! the printbuffer state, ported from cJSON.c:1380–1452 (value dispatch),
//! 1552–1611 (array), 1732–1845 (object).
//!
//! The C's `printbuffer` (`ensure`/`update_offset`, cJSON.c:447–544) exists to
//! grow a manual byte buffer safely — its integer-overflow guard (2683d4d) and
//! offset double-check are exactly what `Vec` growth provides intrinsically, so
//! module 4's print half reduced to `Vec<u8>` plus the two fields the format
//! actually observes: `format` and `depth`.
//!
//! **Module 15 (`entry-opts`) put half of that back, and the reason is worth stating.** That
//! judgement was right for `cJSON_Print`/`PrintUnformatted`/`PrintBuffered`,
//! where the buffer always grows and no caller can see how much was asked for.
//! `cJSON_PrintPreallocated` (cJSON.c:1305) sets `noalloc`, and in that mode
//! `ensure` cannot grow — it returns NULL — so its arithmetic becomes the
//! function's *entire* success predicate. The accounting is the observable.
//! So `Printer` now carries `limit: Option<usize>`: `None` is the growable
//! printer, byte-identical to before (`ensure` is an unconditional `Some`);
//! `Some(n)` is the C's `noalloc` printbuffer of total capacity `n`, and each
//! of the C's fifteen `ensure(output_buffer, needed)` call sites is mirrored
//! with the same `needed`.
//!
//! The predicate, read off cJSON.c:469–472 — `needed += p->offset + 1;` then
//! `if (needed <= p->length) return ...; if (p->noalloc) return NULL;` — is
//!
//! ```text
//!     offset + needed + 1 <= length
//! ```
//!
//! The `+ 1` is a reserved NUL slot. It is why `cJSON_PrintPreallocated`
//! **needs `strlen(output) + 2` bytes, not `strlen(output) + 1`** — a buffer
//! sized exactly for the string and its terminator returns `false`. That is
//! not a guess: every site's requirement works out to `offset_after + 2` (the
//! writers advance `offset` by `needed - 1`, or by `needed` at the two sites
//! that do not write their own NUL), so the binding constraint is always the
//! last one, at `printed_len + 2`. `boundary_is_printed_len_plus_two` below
//! asserts that over a corpus, and `matrix-opts.json` asserts it against the C.
//!
//! The general form of that mistake is LESSONS #41: dropping C machinery as
//! "subsumed by a safer construct" asserts that no caller can observe it, and
//! that is quantified over the entry points you have PORTED, not over the code.
//! The entry points this printer's `Vec`-only form was sound for are
//! `cJSON_Print`, `cJSON_PrintUnformatted` and `cJSON_PrintBuffered` — named
//! here, per that lesson, so the next entry point that arrives has a list to
//! check itself against instead of an argument to re-derive.
//!
//! The sites are mirrored anyway rather than collapsed to that closed form:
//! the theorem is a property of *these fifteen* `needed` values, and a future
//! entry point with different accounting would silently invalidate it while a
//! per-site model just keeps working (LESSONS #26 — a shortcut that is true of
//! today's driver is not a property of the code).
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

/// The C's `INT_MAX`, which `ensure` refuses to exceed (cJSON.c:463). Spelled
/// as a literal rather than `i32::MAX as usize` so no cast appears in a crate
/// that denies `cast_possible_truncation`.
const C_INT_MAX: usize = 0x7fff_ffff;

struct Printer {
    out: Vec<u8>,
    format: bool,
    depth: usize,
    /// `None` = the growable printer (`cJSON_Print`, `PrintUnformatted`,
    /// `PrintBuffered`): `Vec` growth is the whole of `ensure`, so the bound
    /// check is a no-op and nothing about those modes can regress.
    /// `Some(n)` = the C's `noalloc` printbuffer of total capacity `n`
    /// (`cJSON_PrintPreallocated`), where `ensure` is the success predicate.
    limit: Option<usize>,
}

impl Printer {
    /// cJSON.c:447 `ensure`, reduced to the half a safe `Vec` cannot supply:
    /// the bounded-capacity refusal. `self.out.len()` is the C's `p->offset` —
    /// every site below calls this immediately BEFORE writing, exactly where
    /// the C does, so the two offsets agree byte for byte.
    fn ensure(&mut self, needed: usize) -> Option<()> {
        // Growable printer: `Vec` growth IS `ensure`, so nothing can refuse.
        let Some(length) = self.limit else {
            return Some(());
        };
        // cJSON.c:457 — `(p->length > 0) && (p->offset >= p->length)`. Implied
        // by the arithmetic below (needed >= 0 makes offset >= length fail
        // anyway), but kept because it is a distinct refusal in the C and a
        // reader comparing the two should not have to re-derive that.
        if length > 0 && self.out.len() >= length {
            return None;
        }
        // cJSON.c:463 — sizes above INT_MAX are refused outright.
        if needed > C_INT_MAX {
            return None;
        }
        // cJSON.c:469 `needed += p->offset + 1` — the +1 is the NUL slot.
        let total = self.out.len().checked_add(needed)?.checked_add(1)?;
        if total <= length {
            Some(())
        } else {
            // cJSON.c:475 `if (p->noalloc) return NULL;`
            None
        }
    }

    /// cJSON.c:1380 `print_value` dispatch.
    fn value(&mut self, v: &Value) -> Option<()> {
        match v {
            // cJSON.c:1392/1401/1410 — `ensure(5)`, `ensure(6)`, `ensure(5)`,
            // i.e. the literal plus its NUL in every case.
            Value::Null => self.literal(b"null")?,
            Value::False => self.literal(b"false")?,
            Value::True => self.literal(b"true")?,
            // cJSON.c:597 `ensure(length + sizeof(""))` — digits plus NUL.
            Value::Number(n) => {
                let printed = print_number(n);
                self.ensure(printed.len().checked_add(1)?)?;
                self.out.extend_from_slice(printed.as_bytes());
            }
            // cJSON.c:964 `ensure(output_length + sizeof("\"\""))`, where
            // `output_length` is the ESCAPED content without its quotes — so
            // `needed` is the printed form (quotes included) plus one for the
            // NUL, which is also what cJSON.c:928's `ensure(sizeof("\"\""))`
            // comes to for the NULL/empty input the port spells as `b""`.
            Value::String(s) => {
                let printed = print_string(s);
                self.ensure(printed.len().checked_add(1)?)?;
                self.out.extend_from_slice(&printed);
            }
            // cJSON.c:1421 `case cJSON_Raw` — the content is passed through
            // VERBATIM, with none of the escaping a String gets. That is the
            // whole point of a Raw node, and the reason it deserves its own
            // differential mode: it is the one way to get unescaped bytes into
            // the printer's output.
            //
            // The C copies `strlen(valuestring) + 1` bytes and then advances by
            // `strlen` (`update_offset`), so the trailing NUL is written and
            // immediately overwritten — the observable output is exactly the
            // bytes up to the first NUL, which is what `Value::Raw` holds
            // (`dom::create_raw` truncates on construction, like the C's
            // `cJSON_strdup`). An empty Raw therefore contributes nothing,
            // printing `{"k":}` — invalid JSON that cJSON emits happily.
            //
            // This arm previously returned None, on the reasoning that a parse
            // can never produce Raw so the driver could not reach it. True at
            // the time and false the moment `construct` put cJSON_CreateRaw on
            // the compared contract (LESSONS #26 again: unreachable-by-the-
            // current-driver is not a property of the code, it is a property of
            // the driver, and it expires without warning). LESSONS #36.
            //
            // cJSON.c:1429 `raw_length = strlen(...) + sizeof("")`, and the
            // memcpy copies all of it — the NUL is written and then overwritten
            // by whatever comes next.
            Value::Raw(s) => {
                self.ensure(s.len().checked_add(1)?)?;
                self.out.extend_from_slice(s);
            }
            Value::Array(items) => self.array(items)?,
            Value::Object(entries) => self.object(entries)?,
        }
        Some(())
    }

    /// The three keyword arms of cJSON.c:1390–1414, which all `ensure` the
    /// literal plus its NUL and then `strcpy`.
    fn literal(&mut self, lit: &[u8]) -> Option<()> {
        self.ensure(lit.len().checked_add(1)?)?;
        self.out.extend_from_slice(lit);
        Some(())
    }

    /// cJSON.c:1552 `print_array` — inline, `", "` when formatted.
    fn array(&mut self, items: &[Value]) -> Option<()> {
        self.ensure(1)?; // cJSON.c:1565 — the `[`
        self.out.push(b'[');
        self.depth = self.depth.saturating_add(1);
        let mut first = true;
        for item in items {
            if !first {
                // cJSON.c:1584 `length = format ? 2 : 1; ensure(length + 1)`
                let length: usize = if self.format { 2 } else { 1 };
                self.ensure(length.saturating_add(1))?;
                self.out.push(b',');
                if self.format {
                    self.out.push(b' ');
                }
            }
            first = false;
            self.value(item)?;
        }
        self.ensure(2)?; // cJSON.c:1601 — `]` plus its NUL
        self.out.push(b']');
        self.depth = self.depth.saturating_sub(1);
        Some(())
    }

    /// cJSON.c:1732 `print_object` — line-per-entry when formatted; keys go
    /// through `print_string` (same NUL-truncation as values, probed:
    /// a NUL-escaped key prints truncated).
    fn object(&mut self, entries: &[(Vec<u8>, Value)]) -> Option<()> {
        // cJSON.c:1744 `length = format ? 2 : 1; ensure(length + 1)`
        let open: usize = if self.format { 2 } else { 1 };
        self.ensure(open.saturating_add(1))?;
        self.out.push(b'{');
        self.depth = self.depth.saturating_add(1);
        if self.format {
            self.out.push(b'\n');
        }
        let mut it = entries.iter().peekable();
        while let Some((key, value)) = it.next() {
            if self.format {
                // cJSON.c:1764 `ensure(output_buffer->depth)` — the tabs, with
                // NO slack for a NUL, because none is written here.
                self.ensure(self.depth)?;
                for _ in 0..self.depth {
                    self.out.push(b'\t');
                }
            }
            let printed = print_string(key);
            self.ensure(printed.len().checked_add(1)?)?; // cJSON.c:964
            self.out.extend_from_slice(&printed);
            // cJSON.c:1783 `length = format ? 2 : 1; ensure(length)` — the ONE
            // site that does not add the NUL slot, because `:`/`:\t` is written
            // without a terminator. Mirrored as the asymmetry it is: rounding
            // it up to `length + 1` would move the failure boundary by a byte
            // on any document whose tightest site is this one.
            let colon = if self.format { 2 } else { 1 };
            self.ensure(colon)?;
            self.out.push(b':');
            if self.format {
                self.out.push(b'\t');
            }
            self.value(value)?;
            // cJSON.c:1803 `length = (format ? 1 : 0) + (next ? 1 : 0)`
            let has_next = it.peek().is_some();
            let sep = usize::from(self.format).saturating_add(usize::from(has_next));
            self.ensure(sep.checked_add(1)?)?;
            if has_next {
                self.out.push(b',');
            }
            if self.format {
                self.out.push(b'\n');
            }
        }
        // cJSON.c:1825 `ensure(format ? depth + 1 : 2)`
        let close = if self.format {
            self.depth.checked_add(1)?
        } else {
            2
        };
        self.ensure(close)?;
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

/// Render a value. Total since module 11 ported `Raw`: every arm now writes
/// bytes, so `None` is unreachable. The `Option` is kept because the C's
/// `print_value` genuinely can fail (`ensure` returns NULL on an allocation
/// failure or the 2683d4d overflow guard), and the driver maps that to its
/// "print failed" exit — dropping it would change the driver's contract for a
/// case the port cannot currently produce but a future arm might.
#[must_use]
pub fn print_value(value: &Value, formatted: bool) -> Option<Vec<u8>> {
    let mut p = Printer {
        out: Vec::new(),
        format: formatted,
        depth: 0,
        limit: None,
    };
    p.value(value)?;
    Some(p.out)
}

/// cJSON.c:1274 `cJSON_PrintBuffered` — print into a buffer pre-sized to
/// `prebuffer`, which still GROWS (`noalloc` is false). The only thing the
/// prebuffer size can change is how often the C reallocs, and the returned C
/// string is byte-identical to `cJSON_Print`'s either way — probed across
/// `prebuffer` 0, 1, 2 and 1024 on a document 20 bytes long. So the one
/// behavior on the compared contract is the guard:
///
/// * `prebuffer < 0` → `NULL` (cJSON.c:1278), here `None`;
/// * otherwise, exactly `print_value`.
///
/// One C behavior is deliberately NOT reproduced, and it is a real difference
/// rather than an oversight: `prebuffer == 0` calls `malloc(0)`, and the C
/// returns `NULL` if that does — a *platform-dependent* answer. glibc returns a
/// unique non-NULL pointer, so the oracle on this host succeeds, and the port
/// succeeds unconditionally. The port's answer is defined everywhere; the C's
/// is not. Recorded in DIVERGENCES.md under "Structural eliminations" rather
/// than ledgered, because on this oracle the two agree and a ledger row that
/// never diverges is stale by construction.
#[must_use]
pub fn print_buffered(value: &Value, prebuffer: i32, formatted: bool) -> Option<Vec<u8>> {
    if prebuffer < 0 {
        return None;
    }
    print_value(value, formatted)
}

/// cJSON.c:1305 `cJSON_PrintPreallocated` — render into a caller-supplied
/// buffer that must NOT grow, returning whether it fit.
///
/// Two of the C's three refusals are structurally gone: `buffer == NULL` and
/// `length < 0` cannot be spelled with a `&mut [u8]`. The third, the capacity
/// refusal, is the whole point and is modelled exactly (see the module header:
/// success iff `length >= printed_len + 2`).
///
/// **The one deliberate behavioral divergence in this module.** On failure the
/// C leaves whatever it managed to write in the caller's buffer — and because
/// every writer terminates its own fragment, that buffer holds a NUL-terminated
/// *prefix* of the document: `{"a":[1,2` reads back as a perfectly plausible,
/// silently truncated JSON fragment. A caller who ignores the `cJSON_bool`
/// (CWE-252) cannot tell it apart from success. This port writes NOTHING on
/// failure, so a partial render can never be mistaken for a whole one. Ledgered
/// as `print-preallocated-no-partial-write`, with the corrected reference
/// oracle in `oracle/make_fixed_core.py` so differential fuzzing has a C that
/// shares the decision (LESSONS #28).
#[must_use]
pub fn print_preallocated(value: &Value, buffer: &mut [u8], formatted: bool) -> bool {
    let mut p = Printer {
        out: Vec::new(),
        format: formatted,
        depth: 0,
        limit: Some(buffer.len()),
    };
    if p.value(value).is_none() {
        return false;
    }
    // `ensure` has already guaranteed `out.len() + 1 <= buffer.len()` at the
    // last site, so both slices below are in range; the asserts are the
    // cheap restatement of that, not a substitute for it.
    let n = p.out.len();
    debug_assert!(n < buffer.len());
    let Some(dst) = buffer.get_mut(..n) else {
        return false;
    };
    dst.copy_from_slice(&p.out);
    let Some(nul) = buffer.get_mut(n) else {
        return false;
    };
    *nul = 0;
    true
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

    /// A corpus wide enough to reach every one of the fifteen `ensure` sites:
    /// the three keywords, a number, strings plain and escaped, Raw (including
    /// the empty one), empty and populated arrays and objects, and nesting deep
    /// enough that a formatted object's `depth + 1` close is not 1.
    fn ensure_corpus() -> Vec<Value> {
        vec![
            Value::Null,
            Value::True,
            Value::False,
            n(0.0),
            n(-12345.0),
            Value::String(b"".to_vec()),
            Value::String(b"xy".to_vec()),
            Value::String(b"a\"b\\c\nd\x01e".to_vec()), // both escape widths
            Value::Raw(b"".to_vec()),
            Value::Raw(b"<raw>".to_vec()),
            Value::Array(vec![]),
            Value::Array(vec![n(1.0), n(2.0)]),
            Value::Object(vec![]),
            Value::Object(vec![(b"a".to_vec(), n(1.0)), (b"bb".to_vec(), Value::Null)]),
            Value::Object(vec![(
                b"k".to_vec(),
                Value::Array(vec![
                    Value::Object(vec![(b"deep".to_vec(), Value::Object(vec![]))]),
                    Value::String(b"s".to_vec()),
                ]),
            )]),
        ]
    }

    /// The module header's theorem, asserted rather than asserted-in-prose:
    /// mirroring the C's fifteen `ensure(needed)` values makes the bounded
    /// printer succeed at exactly `printed_len + 2` and fail at one byte less.
    /// If a future site is added with different accounting this test is what
    /// notices that the closed form stopped holding.
    #[test]
    fn boundary_is_printed_len_plus_two() {
        for v in ensure_corpus() {
            for formatted in [false, true] {
                let printed = print_value(&v, formatted).unwrap();
                let need = printed.len() + 2;

                let mut buf = vec![0xAA_u8; need];
                assert!(
                    print_preallocated(&v, &mut buf, formatted),
                    "{printed:?} should fit in {need}"
                );
                assert_eq!(&buf[..printed.len()], &printed[..]);
                assert_eq!(buf[printed.len()], 0, "NUL terminator");

                let mut tight = vec![0xAA_u8; need - 1];
                assert!(
                    !print_preallocated(&v, &mut tight, formatted),
                    "{printed:?} must NOT fit in {} (strlen + 1)",
                    need - 1
                );
            }
        }
    }

    /// The deliberate divergence: a failed `print_preallocated` leaves the
    /// caller's buffer byte-for-byte as it was. The C leaves a NUL-terminated
    /// truncation that reads back as a smaller, plausible document.
    #[test]
    fn failure_writes_nothing() {
        let v = Value::Object(vec![(b"a".to_vec(), Value::Array(vec![n(1.0), n(2.0)]))]);
        let printed = print_value(&v, false).unwrap(); // {"a":[1,2]}
        for len in 0..printed.len() + 2 {
            let mut buf = vec![0xAA_u8; len];
            assert!(!print_preallocated(&v, &mut buf, false), "len {len}");
            assert!(buf.iter().all(|&b| b == 0xAA), "len {len} was written to");
        }
    }

    #[test]
    fn print_buffered_matches_unbuffered_and_refuses_negative() {
        let v = Value::Object(vec![(b"a".to_vec(), n(1.0))]);
        assert_eq!(print_buffered(&v, -1, false), None);
        // probed against the oracle: 0, 1, 2 and 1024 all give the same bytes
        for prebuffer in [0, 1, 2, 1024] {
            assert_eq!(
                print_buffered(&v, prebuffer, false).unwrap(),
                print_value(&v, false).unwrap()
            );
        }
    }

    /// The growable printer must be untouched by the `ensure` restructuring:
    /// with `limit: None` every site is a no-op, so no input can newly fail.
    #[test]
    fn growable_printer_never_fails() {
        for v in ensure_corpus() {
            for formatted in [false, true] {
                assert!(print_value(&v, formatted).is_some());
            }
        }
    }
}
