#!/usr/bin/env bash
# Build the C reference shared library (pristine cJSON + the single-shot shims),
# so lib_diff can drive it against the Rust cdylib (libcjson_rs.so).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../c"
CC="${CC:-cc}"
"$CC" -O2 -Wall -Wextra -fPIC -shared -I"$SRC" \
    "$SRC/cJSON.c" "$HERE/shim.c" "$HERE/../oracle/cjson_modes.c" \
    -lm -o "$HERE/libcjson_c.so"
echo "built $HERE/libcjson_c.so"
