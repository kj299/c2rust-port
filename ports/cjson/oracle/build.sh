#!/usr/bin/env bash
# Build the C oracle driver against the vendored, unmodified cJSON source.
# Output: ./cjson_oracle (gitignored; run.sh / capture rebuild it).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../c"
CC="${CC:-cc}"
# -O2 like a real build; -lm for cJSON's math.h (isnan/isinf/floor). No warnings
# suppressed — the vendored source must compile clean at -Wall.
"$CC" -O2 -Wall -Wextra -I"$SRC" \
    "$HERE/driver.c" "$HERE/cjson_modes.c" "$HERE/cjson_utils_modes.c" \
    "$SRC/cJSON.c" "$SRC/cJSON_Utils.c" \
    -lm -o "$HERE/cjson_oracle"
echo "built $HERE/cjson_oracle"
