#!/usr/bin/env python3
"""Golden corpus manager — capture, version, and replay the oracle's output, and
flag when the *oracle itself* is nondeterministic (so you don't enshrine noise as
truth). Complements diff_run.py: golden is for when the reference binary can't run
in CI (capture once, replay the stored output forever) and for locking output
*format* when the reference can't run on the target at all.

  capture --oracle B --matrix M --corpus DIR [--repeats N] [--ignore-exit]
      Run the oracle N times per case; if all N normalize-equal (stdout AND
      exit code), store the golden output plus the exit code. If they differ,
      report the nondeterministic case (its unstable lines) so you can extend
      normalize.py rather than bake in flakiness. A case where the oracle TIMES
      OUT is refused outright — a hang must never become the golden truth.

  replay --rust B --matrix M --corpus DIR [--ignore-exit]
      Run the Rust binary and compare stdout to the stored golden and the exit
      code to the stored <case>.rc (fidelity is stdout AND exit code —
      LESSONS #4; `--ignore-exit` opts out for tools without stable codes).
      A rust-side timeout is a FAIL. Missing golden = a case captured after
      the fact; run capture first.

Golden files are plain text under DIR/<case>.golden (+ DIR/<case>.rc for the
exit code) — diff-friendly, reviewable, committed. An oracle-substitution
wrapper for diff_run.py should emit the .golden and exit with the .rc value.
Usage: golden.py {capture,replay,--self-test} ...
"""
from __future__ import annotations

import argparse
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "..", "differential"))
import normalize as N          # noqa: E402
import diff_run as D           # noqa: E402  (reuse run_one / load_matrix)


def capture(oracle, matrix_path, corpus, repeats, sort, mask_numbers, ignore_exit=False):
    os.makedirs(corpus, exist_ok=True)
    matrix = D.load_matrix(matrix_path)
    norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
    nondet, timeouts, stored = [], [], 0
    for case in matrix:
        name = case["name"]
        runs = [D.run_one(oracle, case) for _ in range(repeats)]
        # A hang is not truth: a timing-out oracle produces the <<TIMEOUT>>
        # sentinel "stably" on every repeat, and storing that as golden would
        # make replay REQUIRE the Rust to hang. Refuse and fail instead.
        if any(timed_out for _out, _rc, timed_out in runs):
            timeouts.append(name)
            continue
        outs = [norm(out) for out, _rc, _t in runs]
        rcs = sorted({rc for _out, rc, _t in runs})
        if len(set(outs)) != 1:
            nondet.append((name, _unstable_lines(outs)))
        elif not ignore_exit and len(rcs) != 1:
            nondet.append((name, [f"exit code varies run-to-run: {rcs}"]))
        else:
            open(os.path.join(corpus, name + ".golden"), "w", encoding="utf-8").write(outs[0])
            if not ignore_exit:
                open(os.path.join(corpus, name + ".rc"), "w", encoding="utf-8").write(f"{rcs[0]}\n")
            stored += 1
    print(f"captured {stored} golden case(s) into {corpus}")
    for name in timeouts:
        print(f"TIMEOUT: {name} — oracle timed out; NOT stored (a hang must not "
              f"become golden truth; fix or design out the blocking call)")
    for name, lines in nondet:
        print(f"NONDETERMINISTIC: {name} — varying lines (extend normalize.py):")
        for ln in lines[:8]:
            print(f"    {ln!r}")
    return 1 if (nondet or timeouts) else 0


def _unstable_lines(runs):
    per = [r.splitlines() for r in runs]
    width = max(len(p) for p in per)
    out = []
    for i in range(width):
        vals = {p[i] if i < len(p) else "<absent>" for p in per}
        if len(vals) > 1:
            out.append(" | ".join(sorted(vals)))
    return out


def replay(rust, matrix_path, corpus, sort, mask_numbers, ignore_exit=False):
    matrix = D.load_matrix(matrix_path)
    norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
    fails = missing = 0
    for case in matrix:
        name = case["name"]
        gpath = os.path.join(corpus, name + ".golden")
        if not os.path.exists(gpath):
            print(f"MISSING GOLDEN: {name} (run capture first)")
            missing += 1
            continue
        golden = open(gpath, encoding="utf-8").read()
        out, rc, timed_out = D.run_one(rust, case)
        if timed_out:
            print(f"[TIMEOUT] {name} (rust exceeded the case timeout — hard fail)")
            fails += 1
            continue
        got = norm(out)
        # Fidelity is stdout AND exit code (LESSONS #4). Corpora captured
        # before .rc sidecars existed get a warning, not a silent pass.
        matched, note = got == golden, ""
        rcpath = os.path.join(corpus, name + ".rc")
        if not ignore_exit:
            if os.path.exists(rcpath):
                try:
                    want_rc = int(open(rcpath, encoding="utf-8").read().strip())
                except (OSError, ValueError):
                    want_rc = None
                    print(f"warn: unreadable {rcpath}; exit code unchecked", file=sys.stderr)
                if want_rc is not None and rc != want_rc:
                    matched = False
                    note = f"  (exit code: golden={want_rc} got={rc})"
            else:
                note = "  (no .rc sidecar; exit code unchecked — re-capture to add)"
        if matched:
            print(f"[MATCH ] {name}{note}")
        else:
            print(f"[FAIL  ] {name}{note}")
            fails += 1
    print(f"\n{len(matrix)} cases, {fails} mismatch(es), {missing} missing golden")
    return 1 if (fails or missing) else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    echo = "/bin/echo" if os.path.exists("/bin/echo") else "echo"
    printf = "/usr/bin/printf" if os.path.exists("/usr/bin/printf") else "printf"
    with tempfile.TemporaryDirectory() as d:
        matrix = os.path.join(d, "m.json")
        # args chosen so echo and printf genuinely differ:
        # echo "%s" "hi" -> "%s hi"  ;  printf "%s" "hi" -> "hi"
        open(matrix, "w").write('[{"name": "fmt", "args": ["%s", "hi"]}]')
        corpus = os.path.join(d, "corpus")
        rc = capture(echo, matrix, corpus, repeats=3, sort=False, mask_numbers=False)
        check("stable oracle → captured, no nondeterminism", rc == 0 and
              os.path.exists(os.path.join(corpus, "fmt.golden")))
        check("replay same binary → match", replay(echo, matrix, corpus, False, False) == 0)
        check("replay divergent binary → fail", replay(printf, matrix, corpus, False, False) == 1)

        # nondeterministic oracle must be flagged, not stored
        nd = os.path.join(d, "nd.sh")
        open(nd, "w").write("#!/bin/sh\nawk 'BEGIN{srand(); print int(rand()*1e9)}'\n")
        os.chmod(nd, 0o755)
        ndm = os.path.join(d, "nd.json")
        open(ndm, "w").write('[{"name": "rng", "args": []}]')
        ndc = os.path.join(d, "ndcorpus")
        rc = capture(nd, ndm, ndc, repeats=5, sort=False, mask_numbers=False)
        check("nondeterministic oracle → flagged, not stored",
              rc == 1 and not os.path.exists(os.path.join(ndc, "rng.golden")))

        # exit-code fidelity survives the golden path (LESSONS #4): same
        # stdout, different exit code must FAIL replay unless --ignore-exit.
        o = os.path.join(d, "o.sh"); open(o, "w").write("#!/bin/sh\necho hi\n"); os.chmod(o, 0o755)
        r = os.path.join(d, "r.sh"); open(r, "w").write("#!/bin/sh\necho hi\nexit 3\n"); os.chmod(r, 0o755)
        ecm = os.path.join(d, "ec.json")
        open(ecm, "w").write('[{"name": "ec", "args": []}]')
        ecc = os.path.join(d, "eccorpus")
        rc = capture(o, ecm, ecc, repeats=2, sort=False, mask_numbers=False)
        check("capture stores the exit code alongside the golden",
              rc == 0 and open(os.path.join(ecc, "ec.rc")).read().strip() == "0")
        check("replay same-stdout wrong-exit → FAIL",
              replay(r, ecm, ecc, False, False) == 1)
        check("replay --ignore-exit accepts exit-only drift",
              replay(r, ecm, ecc, False, False, ignore_exit=True) == 0)

        # a hanging oracle must be refused, never enshrined as golden
        slow = os.path.join(d, "slow.sh")
        open(slow, "w").write("#!/bin/sh\nsleep 2\n"); os.chmod(slow, 0o755)
        tm = os.path.join(d, "t.json")
        open(tm, "w").write('[{"name": "hang", "args": [], "timeout": 0.4}]')
        tc = os.path.join(d, "tcorpus")
        rc = capture(slow, tm, tc, repeats=2, sort=False, mask_numbers=False)
        check("hanging oracle → refused, no golden stored",
              rc == 1 and not os.path.exists(os.path.join(tc, "hang.golden")))
        # and a hanging rust must FAIL replay even against a hang-free golden
        open(os.path.join(tc, "hang.golden"), "w").write("hi\n")
        check("hanging rust → replay FAIL",
              replay(slow, tm, tc, False, False) == 1)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    for name in ("capture", "replay"):
        s = sub.add_parser(name)
        s.add_argument("--oracle" if name == "capture" else "--rust", required=True, dest="binary")
        s.add_argument("--matrix", required=True)
        s.add_argument("--corpus", required=True)
        s.add_argument("--sort", action="store_true")
        s.add_argument("--mask-numbers", action="store_true")
        s.add_argument("--ignore-exit", action="store_true",
                       help="don't capture/compare exit codes (tools without stable codes)")
        if name == "capture":
            s.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.cmd == "capture":
        return capture(args.binary, args.matrix, args.corpus, args.repeats,
                       args.sort, args.mask_numbers, args.ignore_exit)
    if args.cmd == "replay":
        return replay(args.binary, args.matrix, args.corpus,
                      args.sort, args.mask_numbers, args.ignore_exit)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
