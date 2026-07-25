//! Module 2 (scalar-parse): `parse_number` / `print_number`, ported from
//! cJSON.c:307–381 and cJSON.c:546–620 with BYTE fidelity as the goal — the
//! differential compares output bytes, and number formatting is where this
//! port is most likely to diverge (flagged as a candidate divergence in
//! DIVERGENCES.md; every helper here exists to make that divergence not happen).
//!
//! The oracle is built without ENABLE_LOCALES (oracle/build.sh), so the C's
//! locale decimal point is always '.', and the port hard-codes the same.

use crate::value::Number;

/// C: `number_c_string[64]`, scan loop bound `i < sizeof - 1` (cJSON.c:311,323).
const NUM_SCAN_CAP: usize = 63;

/// cJSON.c:546 `compare_double` — relative-epsilon equality, used by the
/// printer's 15-vs-17-digit round-trip check (NOT exact `==`) and by
/// `dom::compare` for `cJSON_Number` equality.
pub(crate) fn compare_double(a: f64, b: f64) -> bool {
    let max_val = a.abs().max(b.abs());
    (a - b).abs() <= max_val * f64::EPSILON
}

/// `strtod`'s longest-valid-prefix semantics over the scanned charset.
///
/// The scan (below) only admits `[0-9+-eE.]`, so the exotic strtod forms
/// ("inf", "nan", hex) are unreachable; on this charset, the longest prefix
/// that `f64::from_str` accepts is exactly what strtod consumes — e.g. `"5-3"`
/// → (5.0, 1), `"1e+"` → (1.0, 1), `"5."` → (5.0, 2). Returns None when no
/// prefix parses (C: `after_end == number_c_string` → parse error).
fn strtod_prefix(s: &str) -> Option<(f64, usize)> {
    for end in (1..=s.len()).rev() {
        if let Ok(v) = s[..end].parse::<f64>() {
            return Some((v, end));
        }
    }
    None
}

/// cJSON.c:307 `parse_number`. Scans the number charset (capped like the C's
/// 64-byte buffer), parses the longest strtod prefix, saturates `valueint`,
/// and reports how many input bytes were consumed.
///
/// Faithful quirk: the consumed length is what *strtod* accepted, not what the
/// scan captured — `"5-3"` consumes one byte and the caller's laxness decides
/// what happens to the rest, exactly as in C.
pub fn parse_number(bytes: &[u8]) -> Option<(Number, usize)> {
    let mut i = 0;
    while i < bytes.len() && i < NUM_SCAN_CAP {
        match bytes[i] {
            b'0'..=b'9' | b'+' | b'-' | b'e' | b'E' | b'.' => {
                // bounded by the two loop guards above
                i = i.saturating_add(1);
            }
            _ => break,
        }
    }
    let s = core::str::from_utf8(&bytes[..i]).ok()?; // charset is pure ASCII
    let (number, consumed) = strtod_prefix(s)?;

    // cJSON.c:365–377: saturate valueint. INT_MAX/INT_MIN are exactly
    // representable as f64, so the comparisons match the C's.
    #[allow(clippy::cast_possible_truncation)] // guarded: |number| < 2^31 here
    let valueint = if number >= f64::from(i32::MAX) {
        i32::MAX
    } else if number <= f64::from(i32::MIN) {
        i32::MIN
    } else {
        number as i32
    };

    Some((
        Number {
            d: number,
            i: valueint,
        },
        consumed,
    ))
}

/// C `printf("%1.*g")` re-implemented byte-for-byte for the two precisions the
/// printer uses (15 and 17).
///
/// Method: format at `{:.prec-1e}` first — that yields the mantissa already
/// ROUNDED to `prec` significant digits, which is what the C standard says %g
/// uses to choose fixed-vs-exponential style (C17 7.21.6.1p8: style e is used
/// when `X < -4 || X >= P`, after rounding). Then reassemble: strip trailing
/// zeros (and a bare point), and print the exponent as `e±NN` with a minimum
/// of two digits — both exactly printf's behavior.
fn fmt_g(d: f64, prec: usize) -> String {
    debug_assert!(prec >= 2);
    let sci = format!("{:.*e}", prec.saturating_sub(1), d);
    let (mant, exp_str) = sci
        .split_once('e')
        .expect("{:e} always contains an exponent");
    let exp: i32 = exp_str.parse().expect("{:e} exponent is an integer");
    let neg = mant.starts_with('-');
    let digits: Vec<u8> = mant.bytes().filter(u8::is_ascii_digit).collect();
    debug_assert_eq!(digits.len(), prec);

    let sign = if neg { "-" } else { "" };
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    // exp is a decimal exponent of a finite f64 (|exp| <= 308) and prec is
    // 15/17: none of this arithmetic can overflow, and `prec as i32` is exact.
    if exp >= -4 && exp < prec as i32 {
        // fixed style, precision P-1-X, then strip trailing zeros
        let (int_part, frac_part): (String, String) = if exp >= 0 {
            let split = (exp as usize) + 1;
            (
                String::from_utf8(digits[..split].to_vec()).expect("ascii"),
                String::from_utf8(digits[split..].to_vec()).expect("ascii"),
            )
        } else {
            let zeros = "0".repeat((-exp - 1) as usize);
            let all = String::from_utf8(digits).expect("ascii");
            ("0".to_string(), format!("{zeros}{all}"))
        };
        let frac = frac_part.trim_end_matches('0');
        if frac.is_empty() {
            format!("{sign}{int_part}")
        } else {
            format!("{sign}{int_part}.{frac}")
        }
    } else {
        // exponential style: d.ddd…e±XX (mantissa trailing zeros stripped,
        // exponent sign always printed, at least two exponent digits)
        let lead = char::from(digits[0]);
        let rest_owned = String::from_utf8(digits[1..].to_vec()).expect("ascii");
        let rest = rest_owned.trim_end_matches('0');
        let esign = if exp < 0 { '-' } else { '+' };
        let eabs = exp.unsigned_abs();
        if rest.is_empty() {
            format!("{sign}{lead}e{esign}{eabs:02}")
        } else {
            format!("{sign}{lead}.{rest}e{esign}{eabs:02}")
        }
    }
}

/// cJSON.c:553 `print_number`, byte-faithful:
///   NaN/Inf → "null"; `d == (double)valueint` → `%d`; else `%1.15g`, and if
///   the printed form doesn't round-trip (per `compare_double`) → `%1.17g`.
pub fn print_number(n: &Number) -> String {
    let d = n.d;
    if d.is_nan() || d.is_infinite() {
        "null".to_string()
    } else if d == f64::from(n.i) {
        format!("{}", n.i)
    } else {
        let printed = fmt_g(d, 15);
        match printed.parse::<f64>() {
            Ok(test) if compare_double(test, d) => printed,
            _ => fmt_g(d, 17),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(d: f64) -> Number {
        // mirror parse-time saturation so tests exercise the printer the way
        // parsing feeds it
        #[allow(clippy::cast_possible_truncation)]
        let i = if d >= f64::from(i32::MAX) {
            i32::MAX
        } else if d <= f64::from(i32::MIN) {
            i32::MIN
        } else {
            d as i32
        };
        Number { d, i }
    }

    // Every expectation below is the OBSERVED output of the C oracle driver
    // (cjson_oracle, v1.7.18, glibc printf) — not printf documentation.
    #[test]
    #[allow(clippy::approx_constant)] // 3.14159 is the corpus vector, not π
    fn print_matches_c_observed() {
        assert_eq!(print_number(&num(42.0)), "42"); // int fast-path
        assert_eq!(print_number(&num(-17.0)), "-17");
        assert_eq!(print_number(&num(0.0)), "0");
        assert_eq!(print_number(&num(-0.0)), "0"); // -0 == 0 → int path, like C
        assert_eq!(print_number(&num(3.14159)), "3.14159");
        assert_eq!(print_number(&num(6.022e23)), "6.022e+23");
        assert_eq!(print_number(&num(2147483647.0)), "2147483647");
        assert_eq!(print_number(&num(-2147483648.0)), "-2147483648");
        assert_eq!(print_number(&num(3e9)), "3000000000"); // > INT_MAX, %g fixed
        assert_eq!(print_number(&num(-1.5e-10)), "-1.5e-10");
        assert_eq!(print_number(&num(1e-5)), "1e-05"); // two-digit exponent pad
        assert_eq!(print_number(&num(0.0001)), "0.0001"); // exp = -4 boundary → fixed
        assert_eq!(print_number(&num(f64::INFINITY)), "null");
        assert_eq!(print_number(&num(f64::NAN)), "null");
        // DBL_MAX pins a real C quirk, OBSERVED against the oracle (not
        // reasoned): the 15-digit form "1.79769313486232e+308" REPARSES AS
        // INF (it rounds above DBL_MAX), and compare_double(inf, d) is
        // `inf <= inf * eps` → true — so C keeps the lossy 15-digit form and
        // never falls back to 17 digits. The port must reproduce that, not
        // "fix" it silently (candidate divergence, see DIVERGENCES.md).
        assert_eq!(
            print_number(&num(1.7976931348623157e308)),
            "1.79769313486232e+308"
        );
        // ...and the follow-on: that lossy form parses to inf, which prints
        // as "null" (also observed against the oracle).
        let (reparsed, _) = parse_number(b"1.79769313486232e+308").unwrap();
        assert!(reparsed.d.is_infinite());
        assert_eq!(print_number(&reparsed), "null");
    }

    #[test]
    #[allow(clippy::approx_constant)] // 3.14159 is the corpus vector, not π
    fn parse_strtod_prefix_semantics() {
        // (input, value, consumed) — strtod's behavior on the scanned charset
        let cases: &[(&str, f64, usize)] = &[
            ("42", 42.0, 2),
            ("-17", -17.0, 3),
            ("3.14159", 3.14159, 7),
            ("6.022e23", 6.022e23, 8),
            ("5.", 5.0, 2),
            ("5-3", 5.0, 1), // '-' admitted by the scan, rejected by strtod
            ("1e+", 1.0, 1), // incomplete exponent: strtod backs off
            ("1e999", f64::INFINITY, 5), // overflow → HUGE_VAL, no error
            ("1e-999", 0.0, 6), // underflow → 0
        ];
        for &(s, want, want_len) in cases {
            let (n, len) = parse_number(s.as_bytes()).expect(s);
            assert_eq!(len, want_len, "consumed length for {s:?}");
            assert_eq!(n.d, want, "value for {s:?}");
        }
        assert!(parse_number(b"-").is_none()); // strtod consumes nothing
        assert!(parse_number(b"e5").is_none()); // no leading digit form
    }

    #[test]
    fn valueint_saturates_like_c() {
        assert_eq!(parse_number(b"3000000000").unwrap().0.i, i32::MAX);
        assert_eq!(parse_number(b"-3000000000").unwrap().0.i, i32::MIN);
        assert_eq!(parse_number(b"2147483647").unwrap().0.i, i32::MAX);
    }
}
