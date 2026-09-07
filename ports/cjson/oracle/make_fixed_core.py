#!/usr/bin/env python3
"""Emit `cJSON_fixed.c` — the vendored cJSON.c with the corrections the port
makes deliberately, so differential FUZZING has a reference that shares them.

Two sites, three corrections:

  1. `cJSON_CreateNumber`   — no longer converts a NaN to `int`.
  2. `cJSON_SetNumberHelper` — same NaN fix, AND it no longer writes number
     fields into a node that is not a number.

## 1. The NaN -> int conversion (cJSON.c:2452-2476, and again at :384)

    if (num >= INT_MAX)            { item->valueint = INT_MAX; }
    else if (num <= (double)INT_MIN) { item->valueint = INT_MIN; }
    else                           { item->valueint = (int)num; }   /* <-- */

A NaN fails BOTH comparisons (every comparison with NaN is false), so it falls
into `(int)num`. Converting a NaN to an integer type is **undefined behavior**
(C17 6.3.1.4p1: the behavior is undefined if the truncated value cannot be
represented). It is not merely theoretical-but-stable, either: it is
architecture-dependent in practice. x86-64's `cvttsd2si` yields the "integer
indefinite" value INT_MIN; AArch64's `fcvtzs` saturates a NaN to 0. So the same
source, compiled from the same C, answers differently per target.

The port takes Rust's `as` cast, which is *defined* to saturate and to map NaN
to 0 — i.e. the port picks the defined answer, which happens to be the one the C
already gives on AArch64. DIVERGENCES.md `create-number-nan-valueint` records
that decision, and `matrix-construct.json` pins it against the PRISTINE oracle
so the divergence is asserted, not assumed.

Why a corrected reference has to exist (LESSONS #28, generalized from
cJSON_Utils.c to the library proper by LESSONS #36): the divergence class is
*predicate-defined* — every NaN payload triggers it, and 8 random bytes are a
NaN roughly once in 2048 — so differential FUZZING against the pristine oracle
would rediscover it endlessly and there is no finite set of fingerprints to pin.
Fuzzing therefore compares the port against THIS corrected C, where both sides
answer 0 and any finding is a REAL port bug.

Reachability, stated honestly: `parse_number` (cJSON.c:374) has the identical
cast but is NOT affected — its character whitelist is `0-9 + - e E .`, so
`strtod` can return an infinity but never a NaN. `cJSON_SetNumberHelper`
(cJSON.c:396) has the identical cast and IS affected. It went unpatched while
the mutation API was unported, because patching code no module exercises adds an
unverified branch to the reference (LESSONS #31, a control nothing invokes); the
`dom-mutate-set` module put it on the compared contract via the `set` driver
mode, so it is patched below.

## 2. `cJSON_SetNumberHelper` has no type check (cJSON.c:384)

Found by RUNNING the setter, not by reading it (LESSONS #38). The mutation spike
read this exact function twice — H4 caught the missing NULL check, H5 caught the
NaN cast — and neither pass mentioned the missing type check, because reading
answers the question you thought to ask. The `set` driver mode put the function
on the compared contract and the very first non-number target disagreed.

    CJSON_PUBLIC(double) cJSON_SetNumberHelper(cJSON *object, double number)
    {
        if (number >= INT_MAX) { object->valueint = INT_MAX; }
        ...
        return object->valuedouble = number;
    }

There is no test of `object->type`, so `cJSON_SetNumberValue(a_string, 5)`
leaves a node whose `type` says `cJSON_String` and whose `valuedouble` says 5.
No accessor will report it (`cJSON_GetNumberValue` checks `cJSON_IsNumber`
first) but `valueint`/`valuedouble` are public struct fields cJSON's own README
tells callers to read, so it is observable type confusion.

The port cannot represent that state — `Value::String` has no number to write —
so the operation is a no-op there, which is also the safer answer. That is a
predicate-defined divergence (EVERY non-number target), so it is corrected here
for the fuzzer and asserted finitely by `matrix-set.json` against the pristine
oracle. See DIVERGENCES.md `set-*-type-confusion` (6 pinned rows).

The pristine vendored source is never modified; this file is generated
(gitignored) and used only to build the fuzz oracle.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "c", "cJSON.c")
OUT = os.path.join(HERE, "cJSON_fixed.c")

# The `num` parameter name is what distinguishes cJSON_CreateNumber's copy of
# this block from the two textually near-identical ones (parse_number and
# cJSON_SetNumberHelper both name it `number`). The occurrence count is asserted
# below rather than trusted, so a vendored-source bump that renames the
# parameter fails loudly instead of patching nothing.
PRISTINE = """\
        /* use saturation in case of overflow */
        if (num >= INT_MAX)
        {
            item->valueint = INT_MAX;
        }
        else if (num <= (double)INT_MIN)
        {
            item->valueint = INT_MIN;
        }
        else
        {
            item->valueint = (int)num;
        }
"""

FIXED = """\
        /* use saturation in case of overflow */
        if (num >= INT_MAX)
        {
            item->valueint = INT_MAX;
        }
        else if (num <= (double)INT_MIN)
        {
            item->valueint = INT_MIN;
        }
        else if (num != num)
        {
            /* fixed: NaN fails both comparisons above and would reach
             * (int)num, which is UNDEFINED BEHAVIOR (C17 6.3.1.4p1) and
             * architecture-dependent in practice: INT_MIN on x86-64,
             * 0 on AArch64. Answer 0, which is what Rust's defined
             * saturating cast gives and what AArch64 already gives. */
            item->valueint = 0;
        }
        else
        {
            item->valueint = (int)num;
        }
"""

# The whole function, signature included: that is what makes the pattern unique
# (the saturation block alone is textually shared with `parse_number`), and it
# is also what lets the type guard go in ahead of the saturation.
SETTER_PRISTINE = """\
CJSON_PUBLIC(double) cJSON_SetNumberHelper(cJSON *object, double number)
{
    if (number >= INT_MAX)
    {
        object->valueint = INT_MAX;
    }
    else if (number <= (double)INT_MIN)
    {
        object->valueint = INT_MIN;
    }
    else
    {
        object->valueint = (int)number;
    }

    return object->valuedouble = number;
}
"""

SETTER_FIXED = """\
CJSON_PUBLIC(double) cJSON_SetNumberHelper(cJSON *object, double number)
{
    if (!cJSON_IsNumber(object))
    {
        /* fixed: the shipped function writes valueint/valuedouble with NO
         * type check, leaving a cJSON_String node that claims to be a
         * string and carries a number. Both fields are public, so that is
         * observable type confusion. The port cannot represent the state
         * at all, so it does nothing here; the return value is unchanged
         * (the shipped code also returns `number`). */
        return number;
    }
    if (number >= INT_MAX)
    {
        object->valueint = INT_MAX;
    }
    else if (number <= (double)INT_MIN)
    {
        object->valueint = INT_MIN;
    }
    else if (number != number)
    {
        /* fixed: identical NaN->int UB to cJSON_CreateNumber above —
         * C17 6.3.1.4p1, INT_MIN on x86-64 and 0 on AArch64. Answer 0. */
        object->valueint = 0;
    }
    else
    {
        object->valueint = (int)number;
    }

    return object->valuedouble = number;
}
"""

# (what it fixes, pristine text, replacement). Each is asserted to occur EXACTLY
# once — see main().
PATCHES = [
    ("cJSON_CreateNumber's NaN->int conversion", PRISTINE, FIXED),
    (
        "cJSON_SetNumberHelper's NaN->int conversion and missing type check",
        SETTER_PRISTINE,
        SETTER_FIXED,
    ),
]


def main():
    text = open(SRC, encoding="utf-8").read()
    for what, pristine, fixed in PATCHES:
        # Count, don't just test membership: `replace(..., 1)` would silently
        # patch only the first of several matches and the oracle would look
        # corrected while the other sites still carried the defect.
        found = text.count(pristine)
        if found != 1:
            print(
                f"error: expected exactly 1 site for {what}, found {found} "
                f"(did the vendored source change?) — update make_fixed_core.py",
                file=sys.stderr,
            )
            return 1
        text = text.replace(pristine, fixed, 1)
    banner = (
        "/* GENERATED by make_fixed_core.py from the vendored cJSON.c — "
        "DO NOT EDIT.\n"
        " * Changes: cJSON_CreateNumber's and cJSON_SetNumberHelper's NaN->int\n"
        " * conversions, and cJSON_SetNumberHelper's missing type check\n"
        " * (DIVERGENCES.md create-number-nan-valueint, set-number-nan-valueint,\n"
        " * set-*-type-confusion). */\n"
    )
    open(OUT, "w", encoding="utf-8").write(banner + text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
