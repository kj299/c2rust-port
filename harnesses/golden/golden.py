#!/usr/bin/env python3
"""Golden corpus manager — capture, version, and replay the oracle's output, and
flag when the *oracle itself* is nondeterministic (so you don't enshrine noise as
truth). Complements diff_run.py: golden is for when the reference binary can't run
in CI (capture once, replay the stored output forever) and for locking output
*format* when the reference can't run on the target at all.

  capture --oracle B --matrix M --corpus DIR [--repeats N] [--ignore-exit]
          [--holdout H] [--validate]
      Run the oracle N times per case; if all N normalize-equal (stdout AND
      exit code), store the golden output plus the exit code. If they differ,
      report the nondeterministic case (its unstable lines) so you can extend
      normalize.py rather than bake in flakiness. A case where the oracle TIMES
      OUT is refused outright — a hang must never become the golden truth.
      --holdout H also captures goldens for a reserved vector set H and records
      it as held-out (see replay). --validate rejects any vector that does not
      pass on the C baseline before admitting it (see below).

  replay --rust B --matrix M --corpus DIR [--ignore-exit] [--holdout H] [--final]
      Run the Rust binary and compare stdout to the stored golden and the exit
      code to the stored <case>.rc (fidelity is stdout AND exit code —
      LESSONS #4; `--ignore-exit` opts out for tools without stable codes).
      A rust-side timeout is a FAIL. Missing golden = a case captured after
      the fact; run capture first. By default this is an ITERATION replay: the
      vectors recorded as held-out are excluded, and it hard-fails if one has
      leaked into the iteration matrix. `--final --holdout H` is the only mode
      that runs the held-back set — the final-acceptance gate.

Held-back vectors (--holdout) and C-baseline validation (--validate) close two
TRACTOR gaps: performers failed *hidden* tests more than the visible ones (an
LLM in the loop overfits vectors it can see), and MIT-LL validates every vector
against the C reference *before* it is allowed to judge a translation. A vector
that "passes" only because it is wrong teaches nothing. `--validate` deems a
vector to pass on the C baseline when the oracle's exit code matches the vector's
`expect_rc` (default 0 — success) and any declared `expect_contains` /
`expect_absent` substring assertion holds against the raw oracle stdout; a vector
that fails is REJECTED, not stored (the prime directive: don't enshrine a C
defect as golden). Held-out vectors are *reserved* — never run during iteration,
run only under `--final` — so the rewrite cannot be tuned to pass them.

Golden files are plain text under DIR/<case>.golden (+ DIR/<case>.rc for the
exit code) — diff-friendly, reviewable, committed. An oracle-substitution
wrapper for diff_run.py should emit the .golden and exit with the .rc value.
capture also records its --sort/--mask-numbers/--ignore-exit flags and the
holdout set in DIR/corpus.meta; replay warns when invoked with different flags
(a silent mismatch produces baffling false failures).
Usage: golden.py {capture,replay,--self-test} ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "..", "differential"))
import normalize as N          # noqa: E402
import diff_run as D           # noqa: E402  (reuse run_one / load_matrix)


META_NAME = "corpus.meta"


def _write_meta(corpus, sort, mask_numbers, ignore_exit, holdout=None):
    meta = {"sort": sort, "mask_numbers": mask_numbers, "ignore_exit": ignore_exit,
            "holdout": list(holdout or [])}
    with open(os.path.join(corpus, META_NAME), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)


def _check_meta(corpus, sort, mask_numbers, ignore_exit):
    """Warn when replay flags differ from the flags the corpus was captured
    with — a mismatch produces baffling false failures with no other hint."""
    mpath = os.path.join(corpus, META_NAME)
    if not os.path.exists(mpath):
        return
    try:
        meta = json.load(open(mpath, encoding="utf-8"))
    except (OSError, ValueError):
        print(f"warn: unreadable {mpath}; cannot verify capture flags", file=sys.stderr)
        return
    now = {"sort": sort, "mask_numbers": mask_numbers, "ignore_exit": ignore_exit}
    drift = {k: (meta.get(k), v) for k, v in now.items() if k in meta and meta[k] != v}
    if drift:
        detail = ", ".join(f"{k}: captured={c} replay={r}" for k, (c, r) in sorted(drift.items()))
        print(f"warn: replay flags differ from capture flags ({detail}) — "
              f"expect false failures; re-capture or match the flags", file=sys.stderr)


def _read_holdout(corpus):
    """The set of case names the corpus recorded as held-out (empty for a corpus
    captured without --holdout, or a pre-holdout corpus)."""
    mpath = os.path.join(corpus, META_NAME)
    if not os.path.exists(mpath):
        return []
    try:
        meta = json.load(open(mpath, encoding="utf-8"))
    except (OSError, ValueError):
        return []
    h = meta.get("holdout", [])
    return h if isinstance(h, list) else []


def _baseline_verdict(case, raw_stdout, rc):
    """None if the vector PASSES on the C baseline, else a human-readable reason.
    'Passes' means the oracle's exit code matches the vector's expectation
    (`expect_rc`, default 0 — success) and any declared `expect_contains` /
    `expect_absent` substring assertion holds against the RAW (un-normalized)
    oracle stdout. A vector that fails on C teaches nothing, or encodes a C bug
    you'd re-port — don't enshrine it as golden. `rc` is None when --ignore-exit
    drops exit-code fidelity, so the code check is skipped."""
    if rc is not None:
        want = case.get("expect_rc", 0)
        if rc != want:
            return f"oracle exited {rc}, expected {want}"
    want_sub = case.get("expect_contains")
    if want_sub is not None and want_sub not in raw_stdout:
        return f"oracle output does not contain expected {want_sub!r}"
    ban_sub = case.get("expect_absent")
    if ban_sub is not None and ban_sub in raw_stdout:
        return f"oracle output contains forbidden {ban_sub!r}"
    return None


def capture(oracle, matrix_path, corpus, repeats, sort, mask_numbers, ignore_exit=False,
            holdout_path=None, validate=False):
    os.makedirs(corpus, exist_ok=True)
    matrix = D.load_matrix(matrix_path)
    holdout_names = []
    if holdout_path:
        hold = D.load_matrix(holdout_path)
        holdout_names = [c["name"] for c in hold]
        overlap = sorted(set(holdout_names) & {c["name"] for c in matrix})
        if overlap:
            print(f"error: {len(overlap)} case(s) are in BOTH the iteration matrix and "
                  f"the holdout — a held-out vector cannot also be iterated on: "
                  f"{', '.join(overlap)}", file=sys.stderr)
            return 2
        cases = list(matrix) + list(hold)
    else:
        cases = list(matrix)

    _write_meta(corpus, sort, mask_numbers, ignore_exit, holdout_names)
    norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
    nondet, timeouts, rejected, stored = [], [], [], 0
    for case in cases:
        name = case["name"]
        runs = [D.run_one(oracle, case) for _ in range(repeats)]
        # A hang is not truth: a timing-out oracle produces the <<TIMEOUT>>
        # sentinel "stably" on every repeat, and storing that as golden would
        # make replay REQUIRE the Rust to hang. Refuse and fail instead.
        if any(timed_out for _out, _rc, timed_out, _err in runs):
            timeouts.append(name)
            continue
        outs = [norm(out) for out, _rc, _t, _e in runs]
        rcs = sorted({rc for _out, rc, _t, _e in runs})
        if len(set(outs)) != 1:
            nondet.append((name, _unstable_lines(outs)))
        elif not ignore_exit and len(rcs) != 1:
            nondet.append((name, [f"exit code varies run-to-run: {rcs}"]))
        else:
            # C-baseline validation (--validate): a vector must pass on the C
            # reference before it may judge Rust. Checked on the stable run.
            reason = (_baseline_verdict(case, runs[0][0], None if ignore_exit else rcs[0])
                      if validate else None)
            if reason is not None:
                rejected.append((name, reason))
                continue
            open(os.path.join(corpus, name + ".golden"), "w", encoding="utf-8").write(outs[0])
            if not ignore_exit:
                open(os.path.join(corpus, name + ".rc"), "w", encoding="utf-8").write(f"{rcs[0]}\n")
            stored += 1
    print(f"captured {stored} golden case(s) into {corpus}")
    if holdout_names:
        print(f"  ({len(holdout_names)} reserved as holdout, excluded from iteration "
              f"replay: {', '.join(holdout_names)})")
    for name in timeouts:
        print(f"TIMEOUT: {name} — oracle timed out; NOT stored (a hang must not "
              f"become golden truth; fix or design out the blocking call)")
    for name, reason in rejected:
        print(f"REJECTED: {name} — {reason}; a vector must pass on the C baseline "
              f"before it may judge Rust (fix the vector or its declared expectation)")
    for name, lines in nondet:
        print(f"NONDETERMINISTIC: {name} — varying lines (extend normalize.py):")
        for ln in lines[:8]:
            print(f"    {ln!r}")
    return 1 if (nondet or timeouts or rejected) else 0


def _unstable_lines(runs):
    per = [r.splitlines() for r in runs]
    width = max(len(p) for p in per)
    out = []
    for i in range(width):
        vals = {p[i] if i < len(p) else "<absent>" for p in per}
        if len(vals) > 1:
            out.append(" | ".join(sorted(vals)))
    return out


def _replay_case(rust, case, corpus, norm, ignore_exit):
    """Compare one case's Rust run against the stored golden (+ .rc sidecar).
    Returns (status, note) with status in {MATCH, FAIL, TIMEOUT, MISSING}."""
    name = case["name"]
    gpath = os.path.join(corpus, name + ".golden")
    if not os.path.exists(gpath):
        return "MISSING", ""
    golden = open(gpath, encoding="utf-8").read()
    out, rc, timed_out, _err = D.run_one(rust, case)
    if timed_out:
        return "TIMEOUT", " (rust exceeded the case timeout — hard fail)"
    got = norm(out)
    # Fidelity is stdout AND exit code (LESSONS #4). Corpora captured before .rc
    # sidecars existed get a warning, not a silent pass.
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
    return ("MATCH" if matched else "FAIL"), note


def replay(rust, matrix_path, corpus, sort, mask_numbers, ignore_exit=False,
           holdout_path=None, final=False):
    _check_meta(corpus, sort, mask_numbers, ignore_exit)
    norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
    matrix = D.load_matrix(matrix_path)
    reserved = set(_read_holdout(corpus))

    if final:
        # Final acceptance: the ONLY mode that runs the held-back vectors.
        if not holdout_path:
            print("error: --final needs --holdout <file> (the reserved acceptance "
                  "set to run at final acceptance)", file=sys.stderr)
            return 2
        hold = D.load_matrix(holdout_path)
        overlap = sorted({c["name"] for c in matrix} & {c["name"] for c in hold})
        if overlap:
            print(f"error: {len(overlap)} case(s) are in BOTH the matrix and the "
                  f"holdout: {', '.join(overlap)}", file=sys.stderr)
            return 2
        cases = [(c, False) for c in matrix] + [(c, True) for c in hold]
    else:
        # Iteration: a held-out vector must never be run here — refuse if one
        # has leaked into the iteration matrix (that would defeat the holdout).
        leaked = [c["name"] for c in matrix if c["name"] in reserved]
        if leaked:
            print(f"HOLDOUT LEAKAGE: {len(leaked)} reserved case(s) present in the "
                  f"iteration matrix and refused — a held-out vector must never be "
                  f"iterated on (run it only via --final): {', '.join(leaked)}",
                  file=sys.stderr)
            return 2
        cases = [(c, False) for c in matrix]

    fails = missing = holdout_run = 0
    for case, is_holdout in cases:
        status, note = _replay_case(rust, case, corpus, norm, ignore_exit)
        tag = " [holdout]" if is_holdout else ""
        if is_holdout:
            holdout_run += 1
        if status == "MISSING":
            print(f"MISSING GOLDEN: {case['name']}{tag} (run capture first)")
            missing += 1
        elif status == "TIMEOUT":
            print(f"[TIMEOUT] {case['name']}{tag}{note}")
            fails += 1
        elif status == "MATCH":
            print(f"[MATCH ] {case['name']}{tag}{note}")
        else:
            print(f"[FAIL  ] {case['name']}{tag}{note}")
            fails += 1

    summary = f"\n{len(cases)} cases, {fails} mismatch(es), {missing} missing golden"
    if final:
        summary += f" (incl. {holdout_run} holdout case(s) run at final acceptance)"
    elif reserved:
        summary += (f"; {len(reserved)} holdout case(s) reserved — excluded from "
                    f"iteration (use --final to run them)")
    print(summary)
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

        # capture flags are recorded; replay with different flags warns
        import contextlib
        import io
        check("capture records its flags in corpus.meta",
              json.load(open(os.path.join(ecc, META_NAME)))["sort"] is False)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            replay(o, ecm, ecc, True, False)  # captured with sort=False
        check("replay with mismatched flags warns",
              "replay flags differ from capture flags" in buf.getvalue())
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            replay(o, ecm, ecc, False, False)
        check("replay with matching flags is quiet", "differ" not in buf.getvalue())

        # ---- held-back vectors (--holdout / --final): a reserved set is
        # excluded from iteration and run only at final acceptance, so the
        # rewrite cannot be tuned to pass it (TRACTOR: hidden > visible fails) --
        pub = os.path.join(d, "pub.json")
        open(pub, "w").write('[{"name": "pub", "args": ["hello"]}]')
        hold = os.path.join(d, "hold.json")
        open(hold, "w").write('[{"name": "hidden", "args": ["secret"]}]')
        hc = os.path.join(d, "holdcorpus")
        rc = capture(echo, pub, hc, repeats=2, sort=False, mask_numbers=False, holdout_path=hold)
        check("capture --holdout stores goldens for both the public and held-out sets",
              rc == 0 and os.path.exists(os.path.join(hc, "pub.golden"))
              and os.path.exists(os.path.join(hc, "hidden.golden")))
        check("capture records the holdout names in corpus.meta",
              json.load(open(os.path.join(hc, META_NAME)))["holdout"] == ["hidden"])
        # a 'rust' that is correct on the public vector but wrong on the hidden one
        rusth = os.path.join(d, "rusth.sh")
        open(rusth, "w").write('#!/bin/sh\nif [ "$1" = secret ]; then echo WRONG; else echo "$@"; fi\n')
        os.chmod(rusth, 0o755)
        check("iteration replay runs only the public set (the held-out golden exists "
              "but is never consulted) → pass",
              replay(rusth, pub, hc, False, False) == 0)
        # leaking the held-out vector into the iteration matrix is refused
        leak = os.path.join(d, "leak.json")
        open(leak, "w").write('[{"name": "pub", "args": ["hello"]},'
                              ' {"name": "hidden", "args": ["secret"]}]')
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            leak_rc = replay(rusth, leak, hc, False, False)
        check("holdout leakage into the iteration matrix is refused",
              leak_rc == 2 and "LEAKAGE" in buf.getvalue())
        check("final acceptance runs the held-out set and catches the overfit → FAIL",
              replay(rusth, pub, hc, False, False, holdout_path=hold, final=True) == 1)
        check("final acceptance passes when the rust is correct on the held-out set too",
              replay(echo, pub, hc, False, False, holdout_path=hold, final=True) == 0)
        check("--final without --holdout errors",
              replay(echo, pub, hc, False, False, final=True) == 2)
        badhold = os.path.join(d, "badhold.json")
        open(badhold, "w").write('[{"name": "pub", "args": ["x"]}]')
        check("capture refuses a holdout that overlaps the iteration matrix",
              capture(echo, pub, os.path.join(d, "hc2"), repeats=1,
                      sort=False, mask_numbers=False, holdout_path=badhold) == 2)

        # ---- C-baseline validation (--validate): a vector must pass on the C
        # reference before it may judge Rust ----
        okv = os.path.join(d, "okv.json")
        open(okv, "w").write('[{"name": "ok", "args": ["hi"]}]')
        check("--validate admits a vector the C baseline passes (exit 0)",
              capture(echo, okv, os.path.join(d, "vc1"), repeats=1,
                      sort=False, mask_numbers=False, validate=True) == 0
              and os.path.exists(os.path.join(d, "vc1", "ok.golden")))
        # oracle that exits nonzero; the default expectation is success (rc 0)
        fail = os.path.join(d, "fail.sh")
        open(fail, "w").write("#!/bin/sh\necho oops\nexit 5\n"); os.chmod(fail, 0o755)
        fv = os.path.join(d, "fv.json")
        open(fv, "w").write('[{"name": "boom", "args": []}]')
        vc2 = os.path.join(d, "vc2")
        check("--validate rejects a vector that fails on C (wrong exit) → not stored",
              capture(fail, fv, vc2, repeats=1, sort=False, mask_numbers=False,
                      validate=True) == 1
              and not os.path.exists(os.path.join(vc2, "boom.golden")))
        check("without --validate the same C-failing vector is still captured (back-compat)",
              capture(fail, fv, os.path.join(d, "vc3"), repeats=1,
                      sort=False, mask_numbers=False) == 0
              and open(os.path.join(d, "vc3", "boom.rc")).read().strip() == "5")
        # a vector may DECLARE the nonzero code it expects (an error-path test)
        fv2 = os.path.join(d, "fv2.json")
        open(fv2, "w").write('[{"name": "boom", "args": [], "expect_rc": 5}]')
        check("--validate honors a declared expect_rc (error-path vector admitted)",
              capture(fail, fv2, os.path.join(d, "vc4"), repeats=1,
                      sort=False, mask_numbers=False, validate=True) == 0)
        # substring assertions run against the raw oracle stdout
        cvm = os.path.join(d, "cvm.json")
        open(cvm, "w").write('[{"name": "sub", "args": ["hello world"],'
                             ' "expect_contains": "world"}]')
        check("--validate admits when expect_contains is satisfied",
              capture(echo, cvm, os.path.join(d, "vc5"), repeats=1,
                      sort=False, mask_numbers=False, validate=True) == 0)
        cvm2 = os.path.join(d, "cvm2.json")
        open(cvm2, "w").write('[{"name": "sub", "args": ["hello"],'
                              ' "expect_contains": "WORLD"}]')
        vc6 = os.path.join(d, "vc6")
        check("--validate rejects when expect_contains is missing → not stored",
              capture(echo, cvm2, vc6, repeats=1, sort=False, mask_numbers=False,
                      validate=True) == 1
              and not os.path.exists(os.path.join(vc6, "sub.golden")))
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
        s.add_argument("--holdout",
                       help="a reserved vector set; capture also stores its goldens and "
                            "marks it held-out, replay runs it only under --final")
        if name == "capture":
            s.add_argument("--repeats", type=int, default=3)
            s.add_argument("--validate", action="store_true",
                           help="reject any vector that does not pass on the C baseline "
                                "(oracle exit != expect_rc, or a declared expect_contains "
                                "/ expect_absent assertion fails) before admitting it")
        else:
            s.add_argument("--final", action="store_true",
                           help="final acceptance: also run the --holdout set (the "
                                "held-back vectors excluded from every iteration replay)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.cmd == "capture":
        return capture(args.binary, args.matrix, args.corpus, args.repeats,
                       args.sort, args.mask_numbers, args.ignore_exit,
                       args.holdout, args.validate)
    if args.cmd == "replay":
        return replay(args.binary, args.matrix, args.corpus,
                      args.sort, args.mask_numbers, args.ignore_exit,
                      args.holdout, args.final)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
