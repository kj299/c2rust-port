#!/usr/bin/env bash
# Build the FUZZ oracle: the vendored C with its KNOWN DEFECTS CORRECTED —
# cJSON_Utils.c's one-line pointer-decode fix (make_fixed_utils.py) and
# cJSON.c's NaN->int conversion (make_fixed_core.py).
#
# Used by diff-fuzz on the modes where the port's intentional fix would
# otherwise make every affected input a (predicate-defined, unpinnable)
# divergence against the pristine oracle — LESSONS #28:
#   `patch`     : every ~0/~1-escaped child key       (utils-tilde-*)
#   `construct` : every NaN element of a number array (create-number-nan-valueint)
# Both classes are infinite, so there is nothing to fingerprint-pin; the finite
# assertion lives in the MATRIX, which still runs against the pristine oracle
# and fails if the divergence ever stops happening (LEDGER-STALE).
#
# LESSONS #36 generalized this from cJSON_Utils.c to cJSON.c itself: the seam
# now takes any number of corrections, and each generator asserts its pristine
# pattern occurs EXACTLY once.
#
# The vendored sources are never modified. Output: ./cjson_oracle_fixed
# (gitignored).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../c"
CC="${CC:-cc}"
"${PYTHON:-python3}" "$HERE/make_fixed_core.py"
"${PYTHON:-python3}" "$HERE/make_fixed_utils.py"
"$CC" -O2 -Wall -Wextra -I"$SRC" \
    "$HERE/driver.c" "$HERE/cjson_modes.c" "$HERE/cjson_utils_modes.c" \
    "$HERE/cJSON_fixed.c" "$HERE/cJSON_Utils_fixed.c" \
    -lm -o "$HERE/cjson_oracle_fixed"
echo "built $HERE/cjson_oracle_fixed"
