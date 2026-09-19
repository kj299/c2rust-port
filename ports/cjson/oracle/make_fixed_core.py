#!/usr/bin/env python3
"""Emit `cJSON_fixed.c` — the vendored cJSON.c with the corrections the port
makes deliberately, so differential FUZZING has a reference that shares them.

Five sites, six corrections:

  1. `cJSON_CreateNumber`     — no longer converts a NaN to `int`.
  2. `cJSON_SetNumberHelper`  — same NaN fix, AND it no longer writes number
     fields into a node that is not a number.
  3. `cJSON_PrintPreallocated` — no longer leaves a partially written,
     NUL-terminated truncation in the caller's buffer when it fails.
  4. `cJSON_AddItemToArray`    — no longer hangs a child off a non-array.
  5. `add_item_to_object`      — no longer stores a key on a non-object.

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

## 3. `cJSON_PrintPreallocated` leaves a truncation behind (cJSON.c:1305)

    return print_value(item, &p);

That is the whole function body after setup: the caller gets a `cJSON_bool` and
nothing else. But `print_value`'s writers each NUL-terminate their own fragment,
so a buffer one byte too small comes back holding a **terminated, well-formed
looking, shorter render** — `{"a":[1,2],"b":"xy` + `\\0`. A caller who ignores
the return value (CWE-252) cannot tell that from a successful print of a smaller
document, and "one byte too small" is the likely case rather than an exotic one:
`ensure` reserves a NUL slot on top of `needed`, so the real requirement is
`strlen + 2` and the obvious `strlen + 1` fails.

The port writes nothing on failure, so the boolean is the only channel. That is
predicate-defined — EVERY buffer length between "the first ensure fails" and the
boundary triggers it, so there is no finite fingerprint set — hence the
correction here and the finite assertions in `matrix-opts.json` against the
PRISTINE oracle (DIVERGENCES.md `opts-prealloc-*`, 5 pinned rows).

The correction is spelled "restore zeros" because this reference cannot know
the caller's prior buffer contents. That is exact for the `opts` driver mode,
which zeroes the buffer before every call on both sides — a coupling this patch
depends on, and the reason the mode zeroes rather than leaving it uninitialized.

## 4/5. The non-container parent (cJSON.c:1973, :2029)

`add_item_to_array` guards a NULL item, a NULL parent and self-reference. It
never asks whether the parent is a container, and `add_item_to_object` only adds
a NULL-key guard before delegating to it. So every public `Add*` entry point
will hang a child off a number, a string, a bool or a null, and will give an
OBJECT a member whose key is NULL.

Both are invisible to the printer — a number with a child still prints `7`, and
a key stored on an array element is dropped by `print_array` — which is how the
class survived fourteen modules. `cJSON_GetArraySize` counts the hung child, and
a NULL-keyed member makes every member AFTER it unreachable through
`cJSON_GetObjectItemCaseSensitive` (whose loop condition tests
`current_element->string != NULL`, cJSON.c:1910) while
`cJSON_GetObjectItem` walks past it.

The port cannot represent either state: `Value::Array(Vec<Value>)` is the only
variant with anywhere to put a child, and a `Value::Object` entry always has a
key. Predicate-defined — EVERY non-container parent triggers it, and a fuzzer
picking its target from a document hits one constantly — so the correction lives
here and `matrix-parent.json` carries the finite assertions against the PRISTINE
oracle (DIVERGENCES.md `scalar-parent-child`, 12 pinned rows).

The patch goes at the two PUBLIC entry points rather than in the shared helper,
because the helper is reached with an object parent from `add_item_to_object`:
a check inside it could only ask "is a container", which would still permit
`cJSON_AddItemToArray(object, item)` and its NULL key. See the comment above
`ADD_ARRAY_PRISTINE`.

## How wide is a correction? Measure it (LESSONS #42)

Every patch in this file is code written against the subject under test, and its
failure mode is a CLEAN report: a correction wider than the decision it encodes
suppresses real divergences indistinguishably from finding none. So adopting one
obliges a measurement, in the same change — fuzz the same driver mode against the
PRISTINE oracle and classify every finding mechanically (parse the descriptor,
assert the set of differing fields is the known one), rather than reading the
first few hunks, which are the common case by construction. For `opts`: 25
distinct pristine-oracle findings, all differing in `ppabuf` alone on a call
where `ppa=0`, with the port's buffer all zeros — the ledgered class exactly.
Recorded in API-COVERAGE.md's sweep table beside the corrected-oracle rows,
which is what makes those rows mean anything.

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

# The whole function again, for the same uniqueness reason as the setter.
PREALLOC_PRISTINE = """\
    p.buffer = (unsigned char*)buffer;
    p.length = (size_t)length;
    p.offset = 0;
    p.noalloc = true;
    p.format = format;
    p.hooks = global_hooks;

    return print_value(item, &p);
}
"""

PREALLOC_FIXED = """\
    p.buffer = (unsigned char*)buffer;
    p.length = (size_t)length;
    p.offset = 0;
    p.noalloc = true;
    p.format = format;
    p.hooks = global_hooks;

    if (print_value(item, &p))
    {
        return true;
    }
    /* fixed: the shipped function returns print_value's verdict and leaves
     * whatever it managed to write in the caller's buffer. Because every
     * writer NUL-terminates its own fragment, that buffer comes back holding a
     * terminated, well-formed-looking, SHORTER render -- indistinguishable
     * from a successful print of a smaller document to any caller that ignores
     * the return value (CWE-252). Write nothing instead.
     *
     * "Write nothing" is spelled as "restore zeros" because this reference
     * cannot know the caller's prior contents; it is exact for the `opts`
     * driver mode, which zeroes the buffer before every call on BOTH sides.
     * That coupling is the whole reason this patch is safe, and it is why the
     * mode zeroes rather than leaving the buffer uninitialized. */
    memset(buffer, 0, (size_t)length);
    return false;
}
"""

# The two PUBLIC entry points, not the shared `add_item_to_array` helper they
# both reach. The helper cannot carry this check: `add_item_to_object` delegates
# to it with an OBJECT parent, so a check inside it could only ask "is a
# container", which would still let cJSON_AddItemToArray(object, item) build the
# NULL-keyed member. Patching the two entry points separately is what matches
# the port, where `add_item_to_array` requires `Value::Array` and `add_named`
# requires `Value::Object`.
#
# The `cJSON_AddItemReference*` variants also call the helper and are left
# alone: API-COVERAGE.md lists them out-of-scope, so patching them would add an
# unverified branch no module exercises (LESSONS #31).
ADD_ARRAY_PRISTINE = """\
/* Add item to array/object. */
CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
    return add_item_to_array(array, item);
}
"""

ADD_ARRAY_FIXED = """\
/* Add item to array/object. */
CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
    if (!cJSON_IsArray(array))
    {
        /* fixed: add_item_to_array guards only a NULL item, a NULL parent and
         * self-reference -- never that the parent is a container. Without this
         * the call hangs a child off a number, a string, a bool or a null
         * (invisible to the printer, but cJSON_GetArraySize counts it), or
         * gives an OBJECT a member with a NULL key, which makes every member
         * after it unreachable through cJSON_GetObjectItemCaseSensitive. The
         * port cannot represent either state at all. */
        return false;
    }
    return add_item_to_array(array, item);
}
"""

ADD_OBJECT_PRISTINE = """\
    if ((object == NULL) || (string == NULL) || (item == NULL) || (object == item))
    {
        return false;
    }
"""

ADD_OBJECT_FIXED = """\
    if ((object == NULL) || (string == NULL) || (item == NULL) || (object == item))
    {
        return false;
    }

    if (!cJSON_IsObject(object))
    {
        /* fixed: the same missing type check on the object side. Without it
         * cJSON_AddItemToObject (and every cJSON_Add*ToObject helper) will
         * store a key on an ARRAY element, which print_array then silently
         * drops -- so a print round-trip loses it. */
        return false;
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
    (
        "cJSON_PrintPreallocated's partial write on failure",
        PREALLOC_PRISTINE,
        PREALLOC_FIXED,
    ),
    (
        "cJSON_AddItemToArray's missing container check",
        ADD_ARRAY_PRISTINE,
        ADD_ARRAY_FIXED,
    ),
    (
        "add_item_to_object's missing container check",
        ADD_OBJECT_PRISTINE,
        ADD_OBJECT_FIXED,
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
        " * conversions, cJSON_SetNumberHelper's missing type check, and\n"
        " * cJSON_PrintPreallocated's partial write on failure\n"
        " * (DIVERGENCES.md create-number-nan-valueint, set-number-nan-valueint,\n"
        " * set-*-type-confusion, opts-prealloc-*). */\n"
    )
    open(OUT, "w", encoding="utf-8").write(banner + text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
