#!/usr/bin/env bash
# Build the FUZZ oracle: pristine cJSON + the CORRECTED cJSON_Utils (one-line
# decode fix, see make_fixed_utils.py). Used only by diff-fuzz on the `patch`
# mode, where the port's intentional decode fix would otherwise make every
# ~escaped child key a (predicate-defined, unpinnable) divergence against the
# pristine oracle (LESSONS #28). Output: ./cjson_oracle_fixed (gitignored).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../c"
CC="${CC:-cc}"
"${PYTHON:-python3}" "$HERE/make_fixed_utils.py"
"$CC" -O2 -Wall -Wextra -I"$SRC" \
    "$HERE/driver.c" "$HERE/cjson_modes.c" "$HERE/cjson_utils_modes.c" \
    "$SRC/cJSON.c" "$HERE/cJSON_Utils_fixed.c" \
    -lm -o "$HERE/cjson_oracle_fixed"
echo "built $HERE/cjson_oracle_fixed"
