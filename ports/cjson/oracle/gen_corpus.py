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


def case(name, mode, stdin, expect_rc, **extra):
    c = {"name": name, "args": [mode], "stdin": stdin, "expect_rc": expect_rc}
    c.update(extra)
    return c


# ---- validation matrix -----------------------------------------------------
MATRIX = [
    # --- accepted round-trips (print-unformatted) ---
    case("empty-object", "print-unformatted", "{}", 0, expect_contains="{}"),
    case("empty-array", "print-unformatted", "[]", 0, expect_contains="[]"),
    case("true", "print-unformatted", "true", 0, expect_contains="true"),
    case("false", "print-unformatted", "false", 0, expect_contains="false"),
    case("null", "print-unformatted", "null", 0, expect_contains="null"),
    case("int", "print-unformatted", "42", 0, expect_contains="42"),
    case("negative", "print-unformatted", "-17", 0, expect_contains="-17"),
    case("zero", "print-unformatted", "0", 0),
    case("float", "print-unformatted", "3.14159", 0),
    case("exponent", "print-unformatted", "6.022e23", 0),
    case("bare-string", "print-unformatted", '"hello"', 0, expect_contains='"hello"'),
    case("string-escapes", "print-unformatted", r'"tab\tnl\nquote\"backslash\\"', 0),
    case("unicode-escape", "print-unformatted", r'"éè"', 0),
    case("surrogate-pair", "print-unformatted", '"\U0001d11e"', 0),  # G-clef 𝄞
    case("nested-object", "print-unformatted",
         '{"a":1,"b":{"c":[true,null,"x"],"d":{}}}', 0, expect_contains='"c"'),
    case("mixed-array", "print-unformatted", '[1,"two",3.0,true,null,{}]', 0),
    case("big-int", "print-unformatted", "2147483647", 0),           # INT_MAX
    case("min-int", "print-unformatted", "-2147483648", 0),          # INT_MIN
    case("large-double", "print-unformatted", "1.7976931348623157e308", 0),
    case("whitespace-around", "print-unformatted", '   {  "k" : 1 }   ', 0,
         expect_contains='"k":1'),
    # nesting AT the limit is accepted (depth 1000); 1001 is not (below)
    case("nesting-limit-ok", "print-unformatted", "[" * 1000 + "]" * 1000, 0),
    # trailing garbage is ACCEPTED by cJSON (lax; parses the first value) — a
    # documented candidate divergence, captured here as the C's actual behavior.
    case("trailing-garbage-lax", "print-unformatted", '{"a":1}trailing', 0,
         expect_contains='{"a":1}'),

    # --- accepted, formatted (print) ---
    case("fmt-object", "print", '{"a":1,"b":2}', 0, expect_contains='"a"'),
    case("fmt-array", "print", "[1,2,3]", 0),

    # --- accepted, minify ---
    case("minify-ws", "minify", '{ "a" : 1 ,  "b" : [ 2 , 3 ] }', 0,
         expect_contains='{"a":1,"b":[2,3]}'),
    case("minify-line-comment", "minify", '{"a":1} // tail comment', 0),
    case("minify-block-comment", "minify", '/* lead */ {"a":1}', 0),
    # #338 regression: an unterminated block comment must NOT OOB — the fixed C
    # yields empty output safely.
    case("minify-unterminated-block", "minify", "/* never closed", 0,
         expect_absent="never"),

    # --- rejected (expect_rc 1): each pins a bug class ---
    case("reject-empty", "print-unformatted", "", 1),
    case("reject-garbage", "print-unformatted", "xyzzy", 1),
    case("reject-unterminated-string", "print-unformatted", '"abc', 1),
    case("reject-unterminated-object", "print-unformatted", '{"a":1', 1),
    case("reject-unterminated-array", "print-unformatted", "[1,2", 1),
    case("reject-trailing-comma", "print-unformatted", "[1,2,]", 1),
    case("reject-comment-in-parse", "print-unformatted", "// c\n{}", 1),
    case("reject-bad-escape", "print-unformatted", r'"\x41"', 1),
    # CVE-class regressions (FLAW-SCAN.md):
    case("cve-lone-surrogate", "print-unformatted", r'"\uD800"', 1),   # a167d9e OOB-read class
    case("cve-nesting-1001", "print-unformatted", "[" * 1001 + "]" * 1001, 1),  # stack-overflow guard
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
    print(f"wrote matrix.json ({len(MATRIX)} cases), holdout.json ({len(HOLDOUT)} cases)")


if __name__ == "__main__":
    main()
