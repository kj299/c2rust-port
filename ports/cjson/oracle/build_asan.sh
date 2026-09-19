#!/usr/bin/env bash
# Build a SANITIZED twin of the C oracle: same sources, same modes, plus
# AddressSanitizer + UndefinedBehaviorSanitizer + leak detection.
#
# Why this exists (LESSONS #40): `driver.c` and `cjson_modes.c` are ~1000 lines
# of C that THIS PORT wrote. They size buffers by hand and juggle ownership by
# hand against an API that transfers it only on success -- `cJSON_InsertItemInArray`
# and `cJSON_ReplaceItemIn*` hand the node back on every failure path, and
# forgetting that leaks. A leak or an overread in there does not change stdout,
# so the differential, the fuzzer and the Rust-side sanitizer gate all stay green
# over it. The gap was found the way these things are: module 14's own probe
# program leaked, LeakSanitizer named the line, and the identical ownership rule
# was three lines away in the driver.
#
# The PLAIN oracle (build.sh) stays uninstrumented -- it has to behave like the
# shipped library, and it is the binary the differential compares against. This
# one is only ever fed to harnesses/oracle-sanitize/sanitize_oracle.py.
#
# Output: ./cjson_oracle_asan (gitignored).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../c"
CC="${CC:-cc}"
# -O1, not -O2: keeps the sanitizer's stack traces readable while still
# exercising the optimizer's view of the code.
"$CC" -O1 -g -Wall -Wextra -fsanitize=address,undefined -I"$SRC" \
    "$HERE/driver.c" "$HERE/cjson_modes.c" "$HERE/cjson_utils_modes.c" \
    "$SRC/cJSON.c" "$SRC/cJSON_Utils.c" \
    -lm -o "$HERE/cjson_oracle_asan"
echo "built $HERE/cjson_oracle_asan"
