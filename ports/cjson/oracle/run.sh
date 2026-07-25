#!/usr/bin/env bash
# Lock the cJSON oracle and prove every vector passes on the C baseline.
# This is the Phase-2 deliverable's runnable proof: build the driver against the
# pristine vendored source, (re)generate the corpus, and validate all 45 vectors
# against the C — a vector that "passes" only because it is wrong teaches nothing
# (OPERATING-GUIDE §5). Fail-closed: any step nonzero aborts.
#
# When the Rust port exists (Phase 4), the same matrix drives the differential:
#   diff_run.py --oracle ./cjson_oracle --rust <rust-driver> \
#               --matrix matrix.json --ledger ../DIVERGENCES.md
# and golden.py replay ... --final runs the reserved holdout at acceptance.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$HERE/../../.."          # repo root (harnesses live here)
PY="${PYTHON:-python3}"

echo "== build the C oracle driver (pristine vendored cJSON) =="
bash "$HERE/build.sh"

echo "== (re)generate the corpus =="
"$PY" "$HERE/gen_corpus.py"

echo "== validate EVERY vector against the C baseline + capture goldens =="
# --validate refuses any vector whose observed rc/assertions don't hold on C;
# --holdout reserves the hidden acceptance set. A clean run proves the matrix is
# a faithful description of the C's behavior — the oracle is locked.
"$PY" "$KIT/harnesses/golden/golden.py" capture \
    --oracle "$HERE/cjson_oracle" --matrix "$HERE/matrix.json" \
    --corpus "$HERE/corpus" --holdout "$HERE/holdout.json" --validate

echo "== spot-check the CVE-class regressions reject as expected =="
fail=0
check_rc() { # <mode> <expect_rc> <label> ; stdin piped
    # capture rc without tripping `set -e` (a rejection exits 1 on purpose)
    local got=0
    "$HERE/cjson_oracle" "$1" >/dev/null 2>&1 || got=$?
    if [ "$got" -ne "$2" ]; then echo "  FAIL $3: rc=$got want=$2"; fail=1
    else echo "  ok   $3 (rc=$got)"; fi
}
"$PY" -c "import sys;sys.stdout.write('['*1001+']'*1001)" | check_rc print-unformatted 1 "nesting-1001 rejected (stack-overflow guard)"
printf '"\\uD800"' | check_rc print-unformatted 1 "lone surrogate rejected (OOB-read class)"
printf '/* never closed' | check_rc minify 0 "unterminated block comment safe (#338)"
[ "$fail" -eq 0 ] || { echo "CVE regression spot-check FAILED"; exit 1; }

echo ""
N=$("$PY" -c "import json;print(len(json.load(open('$HERE/matrix.json')))+len(json.load(open('$HERE/holdout.json'))))")
echo "===== ORACLE LOCKED — $N vectors validated against cJSON v1.7.18 ====="
echo "Next (Phase 4): port module 1 and run diff_run/lib_diff against this oracle."
