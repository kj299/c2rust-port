#!/usr/bin/env python3
"""Performance gate — a Rust port that is far slower than the C is a *specific
bug*, not "the cost of Rust": a needless copy, a missed `--release` build, bounds
checks in a hot loop, an accidental O(n^2). This gate measures the Rust rewrite
against the C oracle over the same input matrix and FAILS when a case exceeds a
ratio threshold (default 1.3x the C median). (PLAYBOOK Phase 4 / synthesis
"performance sanity"; the number that was prose until now.)

It reuses `diff_run.run_one`, so the spawn/stdin/env/timeout semantics — and the
fail-closed timeout handling (a hang is not "slow", it's a failure) — are exactly
the differential's. Timing is wall-clock around each run; the reported statistic
is the MEDIAN of `--repeats` runs (robust to a single scheduling hiccup), and the
ratio is rust_median / oracle_median per case.

Measurement honesty: a case whose oracle median is below `--floor-ms` (default 3)
is dominated by process-spawn overhead, not the work under test — its ratio is
noise, so it is reported as UNMEASURABLE (not a pass, not a fail) and you are told
to give it a bigger workload. Silent truncation reads as coverage; this doesn't.

Usage:
  perf_gate.py --oracle PATH --rust PATH --matrix FILE
               [--repeats N] [--threshold R] [--floor-ms MS] [--json]
  perf_gate.py --self-test
Exit: 0 = every measurable case within threshold; 1 = a case over threshold, a
timeout, or an unmeasurable case (needs a real workload); 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "differential"))
import diff_run as D          # noqa: E402  (reuse run_one / load_matrix)


def _median_time(binary, case, repeats):
    """Median wall-clock (seconds) over `repeats` runs, plus whether any run
    timed out. Times `diff_run.run_one` so spawn/stdin/env/timeout match the
    differential exactly; the tiny constant decode overhead cancels in the
    oracle/rust ratio."""
    times, timed_out = [], False
    for _ in range(repeats):
        t0 = time.perf_counter()
        _out, _rc, to, _err = D.run_one(binary, case)
        times.append(time.perf_counter() - t0)
        timed_out = timed_out or to
    return statistics.median(times), timed_out


def measure(oracle_bin, rust_bin, matrix, repeats, threshold, floor_ms):
    floor_s = floor_ms / 1000.0
    results = []
    for case in matrix:
        name = case["name"]
        o_med, o_to = _median_time(oracle_bin, case, repeats)
        r_med, r_to = _median_time(rust_bin, case, repeats)
        if o_to or r_to:
            verdict, ratio = "TIMEOUT", None
        elif o_med < floor_s:
            # Too fast to attribute to the code under test — spawn-dominated.
            verdict, ratio = "UNMEASURABLE", (r_med / o_med if o_med else None)
        else:
            ratio = r_med / o_med
            verdict = "OK" if ratio <= threshold else "SLOW"
        results.append({
            "name": name, "verdict": verdict,
            "oracle_median_ms": round(o_med * 1000, 3),
            "rust_median_ms": round(r_med * 1000, 3),
            "ratio": None if ratio is None else round(ratio, 3),
            "threshold": threshold,
        })
    return results


def run(oracle_bin, rust_bin, matrix_path, repeats, threshold, floor_ms, as_json):
    results = measure(oracle_bin, rust_bin, D.load_matrix(matrix_path),
                      repeats, threshold, floor_ms)
    bad = [r for r in results if r["verdict"] in ("SLOW", "TIMEOUT", "UNMEASURABLE")]
    if as_json:
        print(json.dumps({"threshold": threshold, "repeats": repeats,
                          "results": results}, indent=2))
    else:
        for r in results:
            ratio = "  n/a" if r["ratio"] is None else f"{r['ratio']:.2f}x"
            print(f"[{r['verdict']:12}] {r['name']:24} "
                  f"C={r['oracle_median_ms']:.1f}ms  Rust={r['rust_median_ms']:.1f}ms  {ratio}")
        n_slow = sum(1 for r in results if r["verdict"] == "SLOW")
        n_to = sum(1 for r in results if r["verdict"] == "TIMEOUT")
        n_un = sum(1 for r in results if r["verdict"] == "UNMEASURABLE")
        print(f"\n{len(results)} cases  (threshold {threshold}x median, {repeats} repeats): "
              f"{n_slow} slow, {n_to} timeout, {n_un} unmeasurable")
        if n_un:
            print("UNMEASURABLE: oracle ran below the floor — give the case a real "
                  "workload (bigger input) so the ratio measures the code, not spawn.")
        if n_slow:
            print("SLOW is a bug to find (a copy, a debug build, bounds checks in a hot "
                  "loop), not 'the cost of Rust' — profile the case.")
    return 1 if bad else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        # Sleep-based stand-ins with a wide separation so the verdict is robust
        # to timing noise: "slow" sleeps ~5x "fast". Floor is small; sleeps are
        # well above it. Identical binary vs itself → ratio ~1 → OK.
        fast = os.path.join(d, "fast.sh")
        open(fast, "w").write("#!/bin/sh\nsleep 0.03\n"); os.chmod(fast, 0o755)
        slow = os.path.join(d, "slow.sh")
        open(slow, "w").write("#!/bin/sh\nsleep 0.15\n"); os.chmod(slow, 0o755)
        tiny = os.path.join(d, "tiny.sh")
        open(tiny, "w").write("#!/bin/sh\nexit 0\n"); os.chmod(tiny, 0o755)
        matrix = [{"name": "c", "args": []}]

        res = measure(fast, fast, matrix, repeats=3, threshold=1.3, floor_ms=3)
        check("same binary → ratio ~1 → OK", res[0]["verdict"] == "OK")

        res = measure(fast, slow, matrix, repeats=3, threshold=1.3, floor_ms=3)
        check("rust ~5x slower → SLOW", res[0]["verdict"] == "SLOW")
        check("SLOW reports a ratio above threshold", res[0]["ratio"] > 1.3)

        res = measure(slow, fast, matrix, repeats=3, threshold=1.3, floor_ms=3)
        check("rust faster than C → OK", res[0]["verdict"] == "OK")

        # a run that exceeds its timeout is a failure, not "slow"
        hang = os.path.join(d, "hang.sh")
        open(hang, "w").write("#!/bin/sh\nsleep 5\n"); os.chmod(hang, 0o755)
        res = measure(fast, hang, [{"name": "h", "args": [], "timeout": 0.3}],
                      repeats=1, threshold=1.3, floor_ms=3)
        check("rust timeout → TIMEOUT (a hang is not 'slow')", res[0]["verdict"] == "TIMEOUT")

        # spawn-dominated case is UNMEASURABLE, not a false OK
        res = measure(tiny, tiny, matrix, repeats=3, threshold=1.3, floor_ms=50)
        check("below the floor → UNMEASURABLE (not a false pass)",
              res[0]["verdict"] == "UNMEASURABLE")

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="C reference binary")
    ap.add_argument("--rust", help="Rust binary under test")
    ap.add_argument("--matrix", help="input matrix (.toml or .json), same format as diff_run")
    ap.add_argument("--repeats", type=int, default=5, help="runs per side; the median is used (default 5)")
    ap.add_argument("--threshold", type=float, default=1.3, help="max rust/oracle median ratio (default 1.3)")
    ap.add_argument("--floor-ms", type=float, default=3.0, help="oracle medians below this are UNMEASURABLE (default 3ms)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.oracle and args.rust and args.matrix):
        ap.print_usage(sys.stderr)
        print("error: --oracle, --rust and --matrix are required (or --self-test)", file=sys.stderr)
        return 2
    return run(args.oracle, args.rust, args.matrix, args.repeats,
               args.threshold, args.floor_ms, args.json)


if __name__ == "__main__":
    sys.exit(main())
