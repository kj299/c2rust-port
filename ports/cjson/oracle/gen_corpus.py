#!/usr/bin/env python3
"""Generate the cJSON differential corpus: matrix.json (validation set) and
holdout.json (hidden acceptance set). Every case is validated against the C
oracle by `golden.py capture --validate`, so `expect_rc` below is the OBSERVED C
behavior (probed 2026-07-25 against v1.7.18), not a guess.

Each case drives the oracle/rust driver: args = [mode], stdin = the JSON bytes.
  mode ∈ {print-unformatted, print, minify}
  expect_rc: 0 = accepted, 1 = rejected (a JSON parser rejecting bad input is a
             RESULT, not a bad vector — that's why we pin the rc).

The rejection cases are the load-bearing ones: each historical-CVE class from
FLAW-SCAN.md gets a regression input here, so "safer than C" is TESTED. The Rust
port must reproduce every rc, and every accepted case byte-for-byte.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def case(name, mode, stdin, expect_rc, mods=("tree",), **extra):
    """LESSONS #19 — `mods` names the port modules whose behavior fully determines this case
    ("scalar" = alloc-node + scalar-parse + dispatch only; "tree" needs
    string/array/object; "minify" needs entry-minify). The per-module matrices
    below filter on it so an increment diffs ONLY inputs its ported modules
    decide — a tree case against a scalar-only port would fail for "not ported
    yet", which is schedule, not divergence."""
    c = {"name": name, "args": [mode], "stdin": stdin, "expect_rc": expect_rc,
         "mods": list(mods)}
    c.update(extra)
    return c


# ---- validation matrix -----------------------------------------------------
MATRIX = [
    # --- accepted round-trips (print-unformatted) ---
    case("empty-object", "print-unformatted", "{}", 0, mods=("tree",), expect_contains="{}"),
    case("empty-array", "print-unformatted", "[]", 0, mods=("tree",), expect_contains="[]"),
    case("true", "print-unformatted", "true", 0, mods=("scalar",), expect_contains="true"),
    case("false", "print-unformatted", "false", 0, mods=("scalar",), expect_contains="false"),
    case("null", "print-unformatted", "null", 0, mods=("scalar",), expect_contains="null"),
    case("int", "print-unformatted", "42", 0, mods=("scalar",), expect_contains="42"),
    case("negative", "print-unformatted", "-17", 0, mods=("scalar",), expect_contains="-17"),
    case("zero", "print-unformatted", "0", 0, mods=("scalar",)),
    case("float", "print-unformatted", "3.14159", 0, mods=("scalar",)),
    case("exponent", "print-unformatted", "6.022e23", 0, mods=("scalar",)),
    case("bare-string", "print-unformatted", '"hello"', 0, mods=("string",), expect_contains='"hello"'),
    case("string-escapes", "print-unformatted", r'"tab\tnl\nquote\"backslash\\"', 0, mods=("string",)),
    case("unicode-escape", "print-unformatted", r'"éè"', 0, mods=("string",)),
    case("surrogate-pair", "print-unformatted", '"\U0001d11e"', 0, mods=("string",)),  # G-clef 𝄞
    case("nested-object", "print-unformatted",
         '{"a":1,"b":{"c":[true,null,"x"],"d":{}}}', 0, mods=("tree",), expect_contains='"c"'),
    case("mixed-array", "print-unformatted", '[1,"two",3.0,true,null,{}]', 0, mods=("tree",)),
    case("big-int", "print-unformatted", "2147483647", 0, mods=("scalar",)),           # INT_MAX
    case("min-int", "print-unformatted", "-2147483648", 0, mods=("scalar",)),          # INT_MIN
    case("large-double", "print-unformatted", "1.7976931348623157e308", 0, mods=("scalar",)),
    case("whitespace-around", "print-unformatted", '   {  "k" : 1 }   ', 0,
         mods=("tree",), expect_contains='"k":1'),
    # nesting AT the limit is accepted (depth 1000); 1001 is not (below)
    case("nesting-limit-ok", "print-unformatted", "[" * 1000 + "]" * 1000, 0, mods=("tree",)),
    # trailing garbage is ACCEPTED by cJSON (lax; parses the first value) — a
    # documented candidate divergence, captured here as the C's actual behavior.
    case("trailing-garbage-lax", "print-unformatted", '{"a":1}trailing', 0,
         mods=("tree",), expect_contains='{"a":1}'),

    # --- accepted, formatted (print) ---
    case("fmt-object", "print", '{"a":1,"b":2}', 0, mods=("tree",), expect_contains='"a"'),
    case("fmt-array", "print", "[1,2,3]", 0, mods=("tree",)),

    # --- accepted, minify ---
    case("minify-ws", "minify", '{ "a" : 1 ,  "b" : [ 2 , 3 ] }', 0,
         mods=("minify",), expect_contains='{"a":1,"b":[2,3]}'),
    case("minify-line-comment", "minify", '{"a":1} // tail comment', 0, mods=("minify",)),
    case("minify-block-comment", "minify", '/* lead */ {"a":1}', 0, mods=("minify",)),
    # #338 regression: an unterminated block comment must NOT OOB — the fixed C
    # yields empty output safely.
    case("minify-unterminated-block", "minify", "/* never closed", 0,
         mods=("minify",), expect_absent="never"),

    case("minify-string-verbatim", "minify", '{ "a b" : "c d" }', 0,
         mods=("minify",), expect_contains='{"a b":"c d"}'),
    case("minify-comment-in-string", "minify", '{"k":"a // b /* c */ d"}', 0,
         mods=("minify",), expect_contains='"a // b /* c */ d"'),
    case("minify-lone-slash-dropped", "minify", '{"a":1/2}', 0, mods=("minify",),
         expect_contains='{"a":12}'),  # the lone-'/' quirk
    case("minify-interleaved-comments", "minify", '[ 1, /* c */ 2, // d\n 3 ]', 0,
         mods=("minify",), expect_contains="[1,2,3]"),
    case("minify-escaped-quote", "minify", r'{"a":"x\"y"}', 0, mods=("minify",),
         expect_contains=r'"x\"y"'),
    # diff-fuzz finding (2026-07-25): C minify doesn't track escape parity, so
    # `\` before a `"` still escapes the quote — "\\" " keeps its space.
    case("minify-escape-parity-quirk", "minify", '"\\\\" "', 0, mods=("minify",),
         expect_contains='" "'),

    # --- rejected (expect_rc 1): each pins a bug class ---
    case("reject-empty", "print-unformatted", "", 1, mods=("scalar",)),
    case("reject-garbage", "print-unformatted", "xyzzy", 1, mods=("scalar",)),
    case("reject-unterminated-string", "print-unformatted", '"abc', 1, mods=("string",)),
    case("reject-unterminated-object", "print-unformatted", '{"a":1', 1, mods=("tree",)),
    case("reject-unterminated-array", "print-unformatted", "[1,2", 1, mods=("tree",)),
    case("reject-trailing-comma", "print-unformatted", "[1,2,]", 1, mods=("tree",)),
    case("reject-comment-in-parse", "print-unformatted", "// c\n{}", 1, mods=("tree",)),
    case("reject-bad-escape", "print-unformatted", r'"\x41"', 1, mods=("string",)),
    # --- scalar-only additions (modules 1-2 differential; all validated vs C) ---
    case("ws-number", "print-unformatted", "   42  ", 0, mods=("scalar",),
         expect_contains="42"),
    case("trailing-after-number", "print-unformatted", "123 456", 0,
         mods=("scalar",), expect_contains="123", expect_absent="456"),
    case("neg-zero", "print-unformatted", "-0", 0, mods=("scalar",)),
    case("num-overflow-inf", "print-unformatted", "1e999", 0, mods=("scalar",),
         expect_contains="null"),   # strtod → HUGE_VAL, isinf → prints null
    case("num-underflow", "print-unformatted", "1e-999", 0, mods=("scalar",)),
    case("small-exp", "print-unformatted", "1e-05", 0, mods=("scalar",)),
    case("exp-boundary-fixed", "print-unformatted", "0.0001", 0, mods=("scalar",)),
    case("reject-lone-minus", "print-unformatted", "-", 1, mods=("scalar",)),
    case("reject-incomplete-exp", "print-unformatted", "1e+", 0, mods=("scalar",),
         expect_contains="1"),      # strtod backs off to "1"; trailing lax
    case("bom-number", "print-unformatted", "\ufeff42", 0, mods=("scalar",),
         expect_contains="42"),
    # DBL_MAX print is LOSSY in C (observed; see rust num.rs test): the printed
    # 15-digit form reparses as inf, which prints as null. Both pinned.
    case("dbl-max-lossy-print", "print-unformatted", "1.7976931348623157e308", 0,
         mods=("scalar",), expect_contains="1.79769313486232e+308"),
    case("dbl-max-reparse-null", "print-unformatted", "1.79769313486232e+308", 0,
         mods=("scalar",), expect_contains="null"),

    # --- string-module additions (all probed against C, 2026-07-25) ---
    case("esc-roundtrip", "print-unformatted", r'"\b\f\n\r\t x \/ \" y"', 0,
         mods=("string",), expect_contains=r'"\b\f\n\r\t x / \" y"'),
    case("esc-slash-unescaped-out", "print-unformatted", r'"a\/b"', 0,
         mods=("string",), expect_contains='"a/b"'),
    case("ctrl-reescape", "print-unformatted", r'"\u0001"', 0,
         mods=("string",), expect_contains=r'"\u0001"'),
    # parse_hex4 returns 0 on INVALID hex → \uZZZZ becomes a NUL, and the
    # printer (walking a C string) truncates there: "a\uZZZZb" prints "a"
    case("invalid-hex-as-nul", "print-unformatted", r'"a\uZZZZb"', 0,
         mods=("string",), expect_contains='"a"', expect_absent="b"),
    case("nul-escape-truncates-print", "print-unformatted", r'"a\u0000b"', 0,
         mods=("string",), expect_contains='"a"', expect_absent="b"),
    case("raw-nul-byte-in-string", "print-unformatted", '"a\x00b"', 0,
         mods=("string",), expect_contains='"a"'),  # a REAL NUL byte in stdin
    case("escaped-surrogate-pair", "print-unformatted", r'"\uD834\uDD1E"', 0,
         mods=("string",), expect_contains='"\U0001d11e"'),
    case("empty-string-value", "print-unformatted", '""', 0, mods=("string",),
         expect_contains='""'),
    case("reject-short-u-before-quote", "print-unformatted", r'"\u041"', 1,
         mods=("string",)),
    case("reject-lone-low-surrogate", "print-unformatted", r'"\uDC00"', 1,
         mods=("string",)),
    case("reject-surrogate-bad-second", "print-unformatted", r'"\uD800\u0041"', 1,
         mods=("string",)),
    case("reject-trailing-backslash", "print-unformatted", '"abc\\', 1,
         mods=("string",)),

    # --- tree-module additions (all probed against C, 2026-07-25) ---
    case("dup-keys-preserved", "print-unformatted", '{"a":1,"a":2}', 0,
         mods=("tree",), expect_contains='{"a":1,"a":2}'),
    case("empty-key", "print-unformatted", '{"":1}', 0, mods=("tree",),
         expect_contains='{"":1}'),
    case("ws-heavy-array", "print-unformatted", "[  1 ,   2  ]", 0,
         mods=("tree",), expect_contains="[1,2]"),
    case("nested-empty-arrays", "print-unformatted", "[[[]]]", 0,
         mods=("tree",), expect_contains="[[[]]]"),
    case("fmt-nested-obj-in-array", "print", '[1,{"a":1}]', 0, mods=("tree",)),
    case("fmt-nested-empty-obj", "print", '{"a":{}}', 0, mods=("tree",)),
    case("reject-missing-colon", "print-unformatted", '{"k" 1}', 1, mods=("tree",)),
    case("reject-missing-comma", "print-unformatted", "[1 2]", 1, mods=("tree",)),
    case("reject-leading-comma", "print-unformatted", "[,1]", 1, mods=("tree",)),
    case("reject-obj-trailing-comma", "print-unformatted", '{"a":1,}', 1, mods=("tree",)),
    case("reject-colon-no-value", "print-unformatted", '{"a":}', 1, mods=("tree",)),

    # CVE-class regressions (FLAW-SCAN.md):
    case("cve-lone-surrogate", "print-unformatted", r'"\uD800"', 1, mods=("string",)),   # a167d9e OOB-read class
    case("cve-nesting-1001", "print-unformatted", "[" * 1001 + "]" * 1001, 1, mods=("tree",)),  # stack-overflow guard
]

# ---- hidden acceptance holdout (different inputs, same spirit) --------------
HOLDOUT = [
    case("hold-nested", "print-unformatted",
         '{"users":[{"id":1,"name":"a"},{"id":2,"name":"b"}],"n":2}', 0,
         expect_contains='"users"'),
    case("hold-deep-500", "print-unformatted", "[" * 500 + "]" * 500, 0),
    case("hold-unicode", "print-unformatted", r'"café ☃"', 0),
    case("hold-exp-number", "print-unformatted", "-1.5e-10", 0),
    case("hold-minify", "minify", '{ "x" : [ 1 , 2 , 3 ] , "y" : true }', 0,
         expect_contains='{"x":[1,2,3],"y":true}'),
    case("hold-reject-truncated", "print-unformatted", '{"a":', 1),
    case("hold-reject-deep-1001", "print-unformatted", "[" * 1001 + "]" * 1001, 1),
]


def main():
    with open(os.path.join(HERE, "matrix.json"), "w") as f:
        json.dump(MATRIX, f, indent=2)
    with open(os.path.join(HERE, "holdout.json"), "w") as f:
        json.dump(HOLDOUT, f, indent=2)
    # The PORTED set grows as modules land; a case is included when every
    # module it depends on is ported. (matrix-scalar.json was this file's
    # first-increment name; matrix-ported.json is the evolving one.)
    ported_mods = {"scalar", "string", "tree", "minify"}
    ported = [c for c in MATRIX if set(c["mods"]) <= ported_mods]
    with open(os.path.join(HERE, "matrix-ported.json"), "w") as f:
        json.dump(ported, f, indent=2)

    # DOM (module 6) differential matrices: every PARSE-testable case (not the
    # minify-only ones) re-run in `dup` mode (parse -> Duplicate -> print; must
    # byte-match a plain round-trip) and `dup-eq` mode (a value equals its
    # duplicate -> always "true"). Both sides run the same mode, so the C's dup
    # output is the reference. Rejections still reject (parse fails first).
    def _remode(cases, mode, expect_contains=None):
        out = []
        for c in cases:
            if "minify" in c["mods"]:
                continue
            d = {"name": f"{mode}-{c['name']}", "args": [mode],
                 "stdin": c["stdin"], "expect_rc": c["expect_rc"], "mods": c["mods"]}
            if expect_contains and c["expect_rc"] == 0:
                d["expect_contains"] = expect_contains
            out.append(d)
        return out
    dup = _remode(MATRIX, "dup")
    # NB: no expect_contains for dup-eq — cJSON_Compare returns FALSE for inf/nan
    # numbers (compare_double(inf,inf) = nan<=inf = false) and for duplicate
    # object keys (first-match can't resolve the 2nd key). Discovered by this
    # matrix's own C-baseline validation. The Rust must MATCH C's true/false,
    # which diff_run checks; asserting "true" here would be wrong.
    dupeq = _remode(MATRIX, "dup-eq")
    with open(os.path.join(HERE, "matrix-dup.json"), "w") as f:
        json.dump(dup, f, indent=2)
    with open(os.path.join(HERE, "matrix-dupeq.json"), "w") as f:
        json.dump(dupeq, f, indent=2)

    # ffi-builder (the Create/Add builder + Get/Is query surface). Two shapes:
    #   build  — stdin is a VARIANT NAME, not JSON; the observable result is the
    #            printed document the builder API produced.
    #   query  — every parse-testable corpus document, looked up by key "a" and
    #            described via the Is* predicates and the struct fields
    #            (type/valueint/valuestring) a C caller reads off the pointer.
    #            Most documents have no "a" and must both answer `missing`;
    #            the object cases exercise the real description path.
    builder = [{"name": f"build-{v}", "args": ["build"], "stdin": v,
                "expect_rc": 0, "mods": ["ffi-builder"]}
               for v in ("flat", "array", "nested", "numbers", "dupkey",
                         "add-null", "empty", "strings")]
    builder += [{"name": f"query-{c['name']}", "args": ["query"],
                 "stdin": "a\n" + c["stdin"], "expect_rc": c["expect_rc"],
                 "mods": ["ffi-builder"]}
                for c in MATRIX if "minify" not in c["mods"]]
    with open(os.path.join(HERE, "matrix-builder.json"), "w") as f:
        json.dump(builder, f, indent=2)
    print(f"wrote matrix.json ({len(MATRIX)} cases), holdout.json ({len(HOLDOUT)}), "
          f"matrix-ported.json ({len(ported)}), matrix-dup.json ({len(dup)}), "
          f"matrix-dupeq.json ({len(dupeq)}), matrix-builder.json ({len(builder)})")


if __name__ == "__main__":
    main()
