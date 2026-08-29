//! Property-based invariants for the cJSON port — a hardening pass that checks
//! properties the differential does NOT: `diff_run` only asserts Rust == C, and
//! the fixed matrices only cover the cases we thought of. These assert the RFCs'
//! and the DOM's own algebra over thousands of generated documents:
//!
//!   * `minify`, `sort`, and parse→print (`roundtrip`) are IDEMPOTENT;
//!   * a value printed by the port re-parses to itself (roundtrip stability);
//!   * RFC-7396 `merge(genmerge(a,b), a)` reconstructs `b` (null-free values);
//!   * RFC-6902 `patch(genpatch(a,b), a)` reconstructs `b`.
//!
//! The generator is a seeded SplitMix64 — no dev-dependency, 100% reproducible,
//! so any failure reproduces from its seed. Reconstruction is checked by
//! `dom::compare` (cJSON_Compare semantics: order-independent for objects), so a
//! legitimate key reordering under patch/merge is not a false failure.
//!
//! Test-only generator arithmetic is bounded by construction; the workspace's
//! overflow/cast lints guard PRODUCTION code, so they are allowed here.
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use cjson_core::modes::run;
use cjson_core::value::Value;
use cjson_core::{dom, parse_with_length, print_value};

/// SplitMix64 — a tiny deterministic PRNG (no external crate).
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A value in `0..n` (n > 0), via a method so no `%` operator trips lints.
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64().rem_euclid(n)
    }
}

/// Clean, round-trippable numbers only (small ints + simple decimals): the
/// float-formatting edge cases are the scalar-parse differential's job, not
/// these algebraic properties.
fn gen_number(rng: &mut Rng) -> f64 {
    const DECIMALS: [f64; 6] = [0.0, 0.5, 1.25, -3.75, 100.0, -42.0];
    if rng.below(2) == 0 {
        // small signed integer
        let m = rng.below(2000) as i64 - 1000;
        m as f64
    } else {
        DECIMALS[rng.below(DECIMALS.len() as u64) as usize]
    }
}

fn gen_string(rng: &mut Rng) -> Vec<u8> {
    // short ASCII, no NUL/control bytes (those are the NUL-truncation quirk's
    // territory, covered by the dedicated tests); include a quote/backslash so
    // escaping is exercised.
    const POOL: &[u8] = b"ab CZ9\"\\/";
    let n = rng.below(6);
    (0..n)
        .map(|_| POOL[rng.below(POOL.len() as u64) as usize])
        .collect()
}

/// Distinct object keys (so merge/patch reconstruction is unambiguous), drawn in
/// varied order so `sort` actually has work to do.
fn gen_keys(rng: &mut Rng, n: usize) -> Vec<Vec<u8>> {
    let mut pool: Vec<Vec<u8>> = [&b"a"[..], b"b", b"c", b"d", b"M", b"Z", b"aa", b"k9"]
        .iter()
        .map(|s| s.to_vec())
        .collect();
    // Fisher-Yates shuffle, then take n.
    let len = pool.len();
    for i in 0..len {
        let j = i + rng.below((len - i) as u64) as usize;
        pool.swap(i, j);
    }
    pool.truncate(n.min(len));
    pool
}

fn gen_value(rng: &mut Rng, depth: u32, allow_null: bool) -> Value {
    let arms = if depth == 0 { 5 } else { 7 };
    match rng.below(arms) {
        0 => {
            if allow_null {
                Value::Null
            } else {
                Value::True
            }
        }
        1 => Value::True,
        2 => Value::False,
        3 => dom::number(gen_number(rng)),
        4 => Value::String(gen_string(rng)),
        5 => {
            let n = rng.below(4);
            Value::Array(
                (0..n)
                    .map(|_| gen_value(rng, depth - 1, allow_null))
                    .collect(),
            )
        }
        _ => {
            let n = rng.below(4) as usize;
            let keys = gen_keys(rng, n);
            Value::Object(
                keys.into_iter()
                    .map(|k| (k, gen_value(rng, depth - 1, allow_null)))
                    .collect(),
            )
        }
    }
}

fn json_of(v: &Value) -> Vec<u8> {
    print_value(v, false).expect("print")
}

fn framed(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    out.push(b'\n');
    out.extend_from_slice(b);
    out
}

#[test]
fn minify_is_idempotent() {
    let mut rng = Rng(0xDEAD_BEEF);
    for _ in 0..3000 {
        let s = json_of(&gen_value(&mut rng, 4, true));
        let once = run("minify", &s).1;
        let twice = run("minify", &once).1;
        assert_eq!(
            once,
            twice,
            "minify not idempotent on {}",
            String::from_utf8_lossy(&s)
        );
    }
}

#[test]
fn roundtrip_is_stable_and_prints_canonically() {
    let mut rng = Rng(0x0000_1234);
    for _ in 0..3000 {
        let s = json_of(&gen_value(&mut rng, 4, true));
        let (rc, once) = run("roundtrip", &s);
        assert_eq!(rc, 0);
        // the port's own printout already IS canonical: parsing+reprinting is a no-op.
        assert_eq!(once, s, "roundtrip changed a port-printed value");
        // and it is a genuine fixed point.
        assert_eq!(run("roundtrip", &once).1, once);
    }
}

#[test]
fn sort_object_is_idempotent_and_ordered() {
    // SortObject sorts an OBJECT's immediate keys (non-recursive). It is
    // idempotent there: re-sorting already-ascending distinct keys is a no-op.
    // (It is deliberately NOT idempotent on ARRAYS — a NULL-key mergesort
    // permutes them each pass; that faithful quirk is pinned elsewhere, so the
    // top-level value here is always a distinct-key object.)
    let mut rng = Rng(0x00AB_CDEF);
    for _ in 0..3000 {
        let n = rng.below(4) as usize + 1;
        let keys = gen_keys(&mut rng, n);
        let obj = Value::Object(
            keys.iter()
                .cloned()
                .map(|k| (k, gen_value(&mut rng, 3, true)))
                .collect(),
        );
        let s = json_of(&obj);
        let (rc, once) = run("sort", &s);
        assert_eq!(rc, 0);
        // idempotent
        assert_eq!(
            run("sort", &once).1,
            once,
            "sort not idempotent on object {}",
            String::from_utf8_lossy(&s)
        );
        // and the top-level keys come out in non-decreasing (case-insensitive) order
        let (Value::Object(entries), _) = parse_with_length(&once).unwrap() else {
            panic!("sorted object did not parse as object");
        };
        for pair in entries.windows(2) {
            let lo: Vec<u8> = pair[0].0.iter().map(u8::to_ascii_lowercase).collect();
            let hi: Vec<u8> = pair[1].0.iter().map(u8::to_ascii_lowercase).collect();
            assert!(
                lo <= hi,
                "keys not sorted: {:?} then {:?}",
                pair[0].0,
                pair[1].0
            );
        }
    }
}

#[test]
fn merge_patch_round_trips() {
    // RFC 7396: applying genmerge(a,b) to a reconstructs b, for null-free values
    // (a JSON null in b is indistinguishable from a delete in a merge patch).
    let mut rng = Rng(0x9999_0001);
    for _ in 0..3000 {
        let a = json_of(&gen_value(&mut rng, 3, false));
        let b = json_of(&gen_value(&mut rng, 3, false));
        let (rc, patch) = run("genmerge", &framed(&a, &b));
        assert_eq!(rc, 0);
        // no-diff → the C emits "null" (not {}); that case can't round-trip, and
        // a==b needs no reconstruction. Assert a and b really are equal there.
        if patch == b"null" {
            let (av, _) = parse_with_length(&a).unwrap();
            let (bv, _) = parse_with_length(&b).unwrap();
            assert!(
                dom::compare(&av, &bv, true),
                "genmerge emitted null for differing docs"
            );
            continue;
        }
        let (rc2, merged) = run("merge", &framed(&patch, &a));
        assert_eq!(rc2, 0);
        let (mv, _) = parse_with_length(&merged).unwrap();
        let (bv, _) = parse_with_length(&b).unwrap();
        assert!(
            dom::compare(&mv, &bv, true),
            "merge round-trip failed:\n  a={}\n  b={}\n  patch={}\n  merged={}",
            String::from_utf8_lossy(&a),
            String::from_utf8_lossy(&b),
            String::from_utf8_lossy(&patch),
            String::from_utf8_lossy(&merged),
        );
    }
}

#[test]
fn json_patch_round_trips() {
    // RFC 6902: applying genpatch(a,b) to a reconstructs b (any values, incl. nulls).
    let mut rng = Rng(0x5150_0007);
    for _ in 0..3000 {
        let a = json_of(&gen_value(&mut rng, 3, true));
        let b = json_of(&gen_value(&mut rng, 3, true));
        let (rc, patch) = run("genpatch", &framed(&a, &b));
        assert_eq!(rc, 0);
        let (rc2, out) = run("patch", &framed(&patch, &a));
        assert_eq!(rc2, 0);
        let doc = out
            .strip_prefix(b"status=0;")
            .unwrap_or_else(|| panic!("patch did not succeed: {}", String::from_utf8_lossy(&out)));
        let (dv, _) = parse_with_length(doc).unwrap();
        let (bv, _) = parse_with_length(&b).unwrap();
        assert!(
            dom::compare(&dv, &bv, true),
            "patch round-trip failed:\n  a={}\n  b={}\n  patch={}\n  result={}",
            String::from_utf8_lossy(&a),
            String::from_utf8_lossy(&b),
            String::from_utf8_lossy(&patch),
            String::from_utf8_lossy(doc),
        );
    }
}
