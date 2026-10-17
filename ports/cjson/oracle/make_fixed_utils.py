#!/usr/bin/env python3
"""Emit `cJSON_Utils_fixed.c` — the vendored cJSON_Utils.c with the corrections
the port makes deliberately, so differential FUZZING has a reference that
shares them. Three sites, three corrections:

  1. `decode_pointer_inplace` decodes `~0`/`~1` per RFC 6901 (the pristine
     function writes to the wrong offset and never copies non-escape bytes
     after an escape, so a Patch child key like `a~1b` corrupts to `a~/`).
     DIVERGENCES.md `utils-tilde-*`.
  2. `detach_path` detaches the leaf key with the caller's case flag. The
     pristine function always calls the case-INSENSITIVE
     `cJSON_DetachItemFromObject`, so under
     `cJSONUtils_ApplyPatchesCaseSensitive` a `remove`/`replace`/`move` of `/A`
     acts on `a`. DIVERGENCES.md `utils-cs-detach-*`. Under the
     case-insensitive entry point the corrected call is the pristine one, so
     the `patch` mode cannot tell the two oracles apart.
  3. `apply_patch`'s add to an object deletes EVERY member the key names
     before appending. The pristine code deletes one, so on a document with the
     key twice the old value stays first and every first-match lookup still
     returns it after a "successful" add. DIVERGENCES.md `utils-add-dup-key*`.

Why a corrected reference exists (LESSONS #28: a predicate-defined intentional
divergence breaks differential FUZZING against the pristine oracle). The port
FIXES both defects, so `diff_run` against the pristine C shows the ledgered
divergences — that is the honest record of how the port differs from *shipped*
cJSON. But differential FUZZING rediscovers each class endlessly (any
`~`-escaped child key; any differently-cased leaf), which is not a finite set
to pin. So the fuzzer compares the Rust port against THIS corrected C: both
behave the same way, so any fuzz finding is a REAL port bug, not an
intentional class. The pristine vendored source is never modified; this file
is generated (gitignored) and used only to build the fuzz oracle.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "c", "cJSON_Utils.c")
OUT = os.path.join(HERE, "cJSON_Utils_fixed.c")

DECODE_PRISTINE = """\
    for (; *string; (void)decoded_string++, string++)
    {
        if (string[0] == '~')
        {
            if (string[1] == '0')
            {
                decoded_string[0] = '~';
            }
            else if (string[1] == '1')
            {
                decoded_string[1] = '/';
            }
            else
            {
                /* invalid escape sequence */
                return;
            }

            string++;
        }
    }
"""

DECODE_FIXED = """\
    for (; *string; (void)decoded_string++, string++)
    {
        if (string[0] == '~')
        {
            if (string[1] == '0')
            {
                decoded_string[0] = '~';
            }
            else if (string[1] == '1')
            {
                decoded_string[0] = '/'; /* fixed: [0], not [1] */
            }
            else
            {
                /* invalid escape sequence */
                return;
            }

            string++;
        }
        else
        {
            decoded_string[0] = string[0]; /* fixed: copy non-escape bytes */
        }
    }
"""

# The whole else-if arm, not just the call: the call alone also appears in
# merge_patch, and LESSONS #36's count below must find exactly one site.
DETACH_PRISTINE = """\
    else if (cJSON_IsObject(parent))
    {
        detached_item = cJSON_DetachItemFromObject(parent, (char*)child_pointer);
    }
"""

DETACH_FIXED = """\
    else if (cJSON_IsObject(parent))
    {
        /* fixed: honour the caller's case flag (utils-cs-detach-*) */
        detached_item = case_sensitive
            ? cJSON_DetachItemFromObjectCaseSensitive(parent, (char*)child_pointer)
            : cJSON_DetachItemFromObject(parent, (char*)child_pointer);
    }
"""

# apply_patch's add-to-object: the pristine code deletes ONE existing member
# with the key and appends the new one, so a duplicated key leaves the old
# value FIRST — where every cJSON lookup (first match) still finds it.
ADD_PRISTINE = """\
        if (case_sensitive)
        {
            cJSON_DeleteItemFromObjectCaseSensitive(parent, (char*)child_pointer);
        }
        else
        {
            cJSON_DeleteItemFromObject(parent, (char*)child_pointer);
        }
        cJSON_AddItemToObject(parent, (char*)child_pointer, value);
"""

ADD_FIXED = """\
        /* fixed: delete EVERY member the key names (utils-add-dup-key*) */
        if (case_sensitive)
        {
            while (cJSON_GetObjectItemCaseSensitive(parent, (char*)child_pointer) != NULL)
            {
                cJSON_DeleteItemFromObjectCaseSensitive(parent, (char*)child_pointer);
            }
        }
        else
        {
            while (cJSON_GetObjectItem(parent, (char*)child_pointer) != NULL)
            {
                cJSON_DeleteItemFromObject(parent, (char*)child_pointer);
            }
        }
        cJSON_AddItemToObject(parent, (char*)child_pointer, value);
"""

PATCHES = [
    ("decode_pointer_inplace's ~0/~1 decode", DECODE_PRISTINE, DECODE_FIXED),
    ("detach_path's case-insensitive leaf detach", DETACH_PRISTINE, DETACH_FIXED),
    ("apply_patch's single delete before an add", ADD_PRISTINE, ADD_FIXED),
]


def main():
    text = open(SRC, encoding="utf-8").read()
    for what, pristine, fixed in PATCHES:
        # LESSONS #36: count, don't just test membership. `replace(..., 1)`
        # patches the FIRST match, so N>1 would leave the others carrying the
        # defect while the file still looked corrected — silent in the SAFE
        # direction, in the one artifact whose whole job is being trustworthy.
        # Same assertion as make_fixed_core.py.
        found = text.count(pristine)
        if found != 1:
            print(f"error: expected exactly 1 site for {what}, found {found} "
                  f"(did the vendored source change?) — update "
                  f"make_fixed_utils.py",
                  file=sys.stderr)
            return 1
        text = text.replace(pristine, fixed, 1)
    banner = ("/* GENERATED by make_fixed_utils.py from the vendored "
              "cJSON_Utils.c — DO NOT EDIT.\n"
              " * Changes: a correct decode_pointer_inplace (DIVERGENCES.md "
              "utils-tilde-*), a\n"
              " * case-flag-honouring leaf detach in detach_path "
              "(utils-cs-detach-*), and an\n"
              " * add that replaces every duplicate of its key "
              "(utils-add-dup-key*). */\n")
    open(OUT, "w", encoding="utf-8").write(banner + text)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
