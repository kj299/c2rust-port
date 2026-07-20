#!/usr/bin/env python3
"""Performance gate — time the Rust rewrite against the C baseline over a workload
matrix and FAIL when the rewrite is more than THRESHOLD× slower (median of N runs;
default 1.3×). Correctness is the differential's job (diff_run.py); this gate is
purely about runtime.

Why 1.3×: the TRACTOR envelope for a competent C→Rust port is ~3–5% median
overhead, ~1.3× worst case. A regression past that is almost never "the cost of
Rust" — it's a *specific* bug: an accidental deep copy, a debug (non-`--release`)
build slipping into the measurement, or bounds checks left in a hot loop. The gate
turns that into a red build instead of a slow surprise in production.

Method: for each workload it discards `--warmup` runs (cold caches / JIT-less
process spin-up), then times `--repeats` runs of each binary and compares the two
MEDIANS (robust to a single scheduler hiccup or GC pause in a way the mean is not).
Output is sent to /dev/null so the harness times execution, not its own pipe
draining — both sides get identical treatment, so the comparison stays fair. A
workload that does not run cleanly on either side (nonzero exit or a timeout) is a
hard FAIL for that workload, never a fast "pass": a gate must not go green because
nothing meaningful ran (LESSONS #6).

The workload matrix is the same schema diff_run.py / golden.py use — a list of
cases with a `name` and `args` (plus optional `stdin`, `env`, `timeout`) — so a
port times the very cases it diffs. Pick workloads with enough work to dwarf
process start-up, or the number measures `fork+exec`, not your code.

Usage:
  perf_gate.py --oracle C_BIN --rust RUST_BIN --matrix FILE
               [--threshold R] [--repeats N] [--warmup K] [--json]
  perf_gate.py --self-test
Exit: 0 = every workload within the threshold; 1 = at least one over (or errored).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "..", "differential"))
import diff_run as D  # noqa: E402  (reuse load_matrix + the case schema/validation)


DEFAULT_THRESHOLD = 1.3
DEFAULT_REPEATS = 7
DEFAULT_WARMUP = 1


def _time_one(binary, case, default_timeout=30):
    """Run one workload once; return (elapsed_seconds, returncode, timed_out).
    stdout/stderr go to /dev/null so we measure the program, not our own output
    handling — applied to both sides, so it stays a fair comparison."""
    argv = [binary] + [str(a) for a in case.get("args", [])]
    env = dict(os.environ)
    env.update({k: str(v) for k, v in case.get("env", {}).items()})
    stdin = case.get("stdin", "")
    t0 = time.perf_counter()
    try:
        p = subprocess.run(
            argv,
            input=stdin.encode() if stdin else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=case.get("timeout", default_timeout),
            env=env,
        )
        return (time.perf_counter() - t0, p.returncode, False)
    except subprocess.TimeoutExpired:
        return (time.perf_counter() - t0, 124, True)
    except FileNotFoundError:
        sys.exit(f"error: binary not found: {binary}")


def _median_time(binary, case, repeats, warmup):
    """Median wall-clock over `repeats` timed runs, after `warmup` discarded
    runs. Returns (median, samples, bad) where `bad` is a reason string if ANY
    timed run failed (nonzero exit / timeout) — a workload that didn't run
    cleanly can't be trusted to time, so the caller fails the gate closed on it."""
    for _ in range(max(0, warmup)):
        _time_one(binary, case)
    samples, bad = [], None
    for _ in range(max(1, repeats)):
        elapsed, rc, timed_out = _time_one(binary, case)
        samples.append(elapsed)
        if timed_out and bad is None:
            bad = f"timed out (> {case.get('timeout', 30)}s)"
        elif rc != 0 and bad is None:
            bad = f"exited {rc}"
    return statistics.median(samples), samples, bad


def gate_one(oracle, rust, case, threshold, repeats, warmup):
    """Time one workload on both binaries and return its verdict dict."""
    o_med, _o_s, o_bad = _median_time(oracle, case, repeats, warmup)
    r_med, _r_s, r_bad = _median_time(rust, case, repeats, warmup)
    # Ratio is rust / oracle. Guard a zero/near-zero baseline: a workload that
    # measures as instantaneous is below timing resolution and its ratio is
    # noise — treat a slower rust as inf so it can't sneak under the threshold.
    if o_med > 1e-6:
        ratio = r_med / o_med
    else:
        ratio = float("inf") if r_med > o_med else 1.0
    errored = o_bad or r_bad
    ok = (not errored) and ratio <= threshold
    return {
        "name": case["name"],
        "oracle_median_s": o_med,
        "rust_median_s": r_med,
        "ratio": ratio,
        "threshold": threshold,
        "repeats": repeats,
        "pass": bool(ok),
        "oracle_error": o_bad,
        "rust_error": r_bad,
    }


def run_gate(oracle, rust, matrix, threshold, repeats, warmup):
    return [gate_one(oracle, rust, case, threshold, repeats, warmup) for case in matrix]


def _report(results, as_json):
    failed = [r for r in results if not r["pass"]]
    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            flag = "PASS" if r["pass"] else "FAIL"
            ratio = r["ratio"]
            ratio_s = "inf" if ratio == float("inf") else f"{ratio:.2f}"
            print(f"[{flag}] {r['name']}: rust {r['rust_median_s'] * 1000:.1f}ms / "
                  f"oracle {r['oracle_median_s'] * 1000:.1f}ms = {ratio_s}× "
                  f"(limit {r['threshold']}×)")
            if r["oracle_error"]:
                print(f"    oracle workload did not run cleanly: {r['oracle_error']}")
            if r["rust_error"]:
                print(f"    rust workload did not run cleanly: {r['rust_error']}")
        threshold = results[0]["threshold"] if results else DEFAULT_THRESHOLD
        print(f"\n{len(results)} workload(s), {len(failed)} over the {threshold}× limit")
        if failed:
            print("A workload past the limit is usually a *specific* bug — an accidental "
                  "copy, a debug (non-release) build, or bounds checks in a hot loop — "
                  "not the inherent cost of Rust. Profile the offending workload.")
    return failed


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        def mkbin(nm, body):
            p = os.path.join(d, nm)
            open(p, "w").write("#!/bin/sh\n" + body + "\n")
            os.chmod(p, 0o755)
            return p

        # Deliberately separated timings so the ratios never live near the
        # threshold: fast ≈ 40ms, slow ≈ 140ms → ~3.5×, comfortably > 1.3×.
        fast = mkbin("fast.sh", "sleep 0.04")
        slow = mkbin("slow.sh", "sleep 0.14")
        case = {"name": "w", "args": []}

        res = run_gate(fast, slow, [case], threshold=1.3, repeats=3, warmup=1)
        check("rust ~3.5× slower than C → gate FAILs",
              res[0]["pass"] is False and res[0]["ratio"] > 1.3)

        res = run_gate(slow, fast, [case], threshold=1.3, repeats=3, warmup=1)
        check("rust faster than C → gate PASSes",
              res[0]["pass"] is True and res[0]["ratio"] < 1.3)

        res = run_gate(fast, slow, [case], threshold=5.0, repeats=3, warmup=1)
        check("--threshold relaxes the gate (same regression passes at 5×)",
              res[0]["pass"] is True)

        med, samples, bad = _median_time(fast, case, repeats=4, warmup=1)
        check("median over N samples, warm-up discarded",
              len(samples) == 4 and bad is None and med > 0)

        # fail-closed: a workload that errors on the rust side must FAIL even
        # under an enormous threshold — a gate must not go green on a non-run.
        boom = mkbin("boom.sh", "exit 7")
        res = run_gate(fast, boom, [case], threshold=1000.0, repeats=3, warmup=0)
        check("workload that errors on rust → FAIL under a huge threshold (fail-closed)",
              res[0]["pass"] is False and res[0]["rust_error"] == "exited 7")

        # a timeout is likewise a hard fail, not an untimed pass
        hang = mkbin("hang.sh", "sleep 2")
        res = run_gate(fast, hang, [{"name": "w", "args": [], "timeout": 0.3}],
                       threshold=1000.0, repeats=2, warmup=0)
        check("workload that times out on rust → FAIL (fail-closed)",
              res[0]["pass"] is False and "timed out" in (res[0]["rust_error"] or ""))

        # main() wiring: nonzero exit on a failing gate, zero within budget
        mf = os.path.join(d, "m.json")
        open(mf, "w").write('[{"name": "w", "args": []}]')
        check("main() exits nonzero when the gate fails",
              main(["--oracle", fast, "--rust", slow, "--matrix", mf,
                    "--repeats", "3", "--warmup", "1"]) == 1)
        check("main() exits zero when the rewrite is within budget",
              main(["--oracle", slow, "--rust", fast, "--matrix", mf,
                    "--repeats", "3", "--warmup", "1"]) == 0)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="the C baseline (reference) binary")
    ap.add_argument("--rust", help="the Rust rewrite under test")
    ap.add_argument("--matrix", help="workload matrix (.toml/.json; same schema as diff_run.py)")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                    help=f"fail if the rust/oracle median ratio exceeds this (default {DEFAULT_THRESHOLD})")
    ap.add_argument("--repeats", type=int, default=DEFAULT_REPEATS,
                    help=f"timed runs per side per workload; the median is compared (default {DEFAULT_REPEATS})")
    ap.add_argument("--warmup", type=int, default=DEFAULT_WARMUP,
                    help=f"warm-up runs discarded before timing (default {DEFAULT_WARMUP})")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.oracle and args.rust and args.matrix):
        ap.print_usage(sys.stderr)
        print("error: --oracle, --rust and --matrix are required", file=sys.stderr)
        return 2

    results = run_gate(args.oracle, args.rust, D.load_matrix(args.matrix),
                       args.threshold, args.repeats, args.warmup)
    failed = _report(results, args.json)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
