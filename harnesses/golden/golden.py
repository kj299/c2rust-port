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
      capture is AUTHORITATIVE over its corpus directory: after it runs, a
      `<case>.golden` exists iff that case was stored on THIS run — any stale
      golden (a case now rejected, timed out, or dropped from the suite) is
      pruned, so a discarded vector can never linger to judge the Rust.
      --holdout H also captures goldens for a reserved set H and records it as
      held-out; re-capturing that corpus without --holdout is refused (it would
      blank the reservation). --validate rejects any vector that does not pass
      on the C baseline (see below).

  replay --rust B --matrix M --corpus DIR [--ignore-exit] [--holdout H] [--final]
      Run the Rust binary and compare stdout to the stored golden and the exit
      code to the stored <case>.rc (fidelity is stdout AND exit code —
      LESSONS #4; `--ignore-exit` opts out for tools without stable codes).
      A rust-side timeout is a FAIL. Missing golden = a case captured after
      the fact; run capture first. By default this is an ITERATION replay: the
      vectors recorded as held-out are excluded, and it hard-fails if one has
      leaked into the iteration matrix. It also fails CLOSED if corpus.meta is
      present-but-unreadable (a tampered/partial reservation record must not
      silently disable the holdout). `--final --holdout H` is the only mode that
      runs the held-back set, and it refuses unless H covers every reserved
      vector — the final-acceptance gate cannot be green-lit while skipping the
      hidden set.

Held-back vectors (--holdout) and C-baseline validation (--validate) close two
TRACTOR gaps: performers failed *hidden* tests more than the visible ones (an
LLM in the loop overfits vectors it can see), and MIT-LL validates every vector
against the C reference *before* it is allowed to judge a translation. A vector
that "passes" only because it is wrong teaches nothing. `--validate` deems a
vector to pass on the C baseline when the oracle's exit code matches the vector's
`expect_rc` (default 0 — success; a DECLARED expect_rc is honored even under
--ignore-exit) and any declared `expect_contains` / `expect_absent` substring
assertion holds against the raw oracle stdout of EVERY repeat; a failing (or
un-checkable) vector is REJECTED, not stored (the prime directive: don't enshrine
a C defect as golden). Held-out vectors are *reserved* — never run during
iteration, run only under `--final` — so the rewrite cannot be tuned to pass them.

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
import subprocess
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "..", "differential"))
import normalize as N          # noqa: E402
import diff_run as D           # noqa: E402  (reuse run_one / load_matrix)


META_NAME = "corpus.meta"


class _CorpusError(Exception):
    """corpus.meta is present but unreadable/malformed — we must not guess."""


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
    """The set of case names the corpus records as held-out. An ABSENT meta is
    a legacy/foreign corpus with no reservation known (returns []); a PRESENT
    but unreadable/malformed meta raises `_CorpusError` — callers must fail
    closed rather than silently drop the holdout protection."""
    mpath = os.path.join(corpus, META_NAME)
    if not os.path.exists(mpath):
        return []
    try:
        meta = json.load(open(mpath, encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise _CorpusError(f"unreadable {mpath}: {e}")
    h = meta.get("holdout", [])
    if not isinstance(h, list):
        raise _CorpusError(f"{mpath} has a non-list 'holdout' field")
    return h


def _prune_corpus(corpus, keep):
    """Delete every <name>.golden / <name>.rc whose <name> is not in `keep`, so
    the corpus holds a golden ONLY for a case stored this run — a rejected,
    nondeterministic, timed-out, or dropped vector can never leave a stale
    golden behind to judge the Rust. Returns the pruned stems."""
    pruned = set()
    try:
        entries = os.listdir(corpus)
    except OSError:
        return pruned
    for fn in entries:
        if fn == META_NAME:
            continue
        stem, ext = os.path.splitext(fn)
        if ext in (".golden", ".rc") and stem not in keep:
            try:
                os.remove(os.path.join(corpus, fn))
                pruned.add(stem)
            except OSError:
                pass
    return pruned


def _validate_vector(case, runs, rcs, ignore_exit):
    """Return None if the vector PASSES on the C baseline, else a reason string.
    'Passes' means the oracle's exit code matches the vector's expectation
    (`expect_rc`, default 0 — a DECLARED expect_rc is enforced even under
    --ignore-exit; only the *default* 0 is skipped when exit isn't tracked) and
    every declared substring assertion (`expect_contains` / `expect_absent`)
    holds against the RAW stdout of EVERY repeat. Malformed assertions are
    rejected (a bad vector, not a crash), and a --validate with nothing to check
    fails closed — a gate must not pass because it inspected nothing (LESSONS #6)."""
    checked = False
    if "expect_rc" in case:
        want = case["expect_rc"]
        if not isinstance(want, int) or isinstance(want, bool):
            return f"expect_rc must be an integer, got {want!r}"
        actual = sorted({rc for _o, rc, _t, _e in runs})
        checked = True
        if actual != [want]:
            return f"oracle exit {actual}, expected {want}"
    elif not ignore_exit:
        checked = True
        if rcs != [0]:
            return f"oracle exit {rcs}, expected 0 (success)"

    for key, want_present in (("expect_contains", True), ("expect_absent", False)):
        if key in case:
            sub = case[key]
            if not isinstance(sub, str):
                return f"{key} must be a string, got {sub!r}"
            if sub == "":
                return f"{key} is empty — not a valid assertion"
            checked = True
            hits = [sub in out for out, _rc, _t, _e in runs]
            if want_present and not all(hits):
                return f"expected every run's output to contain {sub!r}"
            if (not want_present) and any(hits):
                return f"expected no run's output to contain {sub!r}"

    if not checked:
        return ("nothing to validate: --ignore-exit disables the default exit check "
                "and the vector declares no expect_rc/expect_contains/expect_absent")
    return None


def capture(oracle, matrix_path, corpus, repeats, sort, mask_numbers, ignore_exit=False,
            holdout_path=None, validate=False):
    os.makedirs(corpus, exist_ok=True)
    matrix = D.load_matrix(matrix_path, allow_empty=True)
    holdout_names = []
    if holdout_path:
        hold = D.load_matrix(holdout_path, allow_empty=True)
        holdout_names = [c["name"] for c in hold]
        overlap = sorted(set(holdout_names) & {c["name"] for c in matrix})
        if overlap:
            print(f"error: {len(overlap)} case(s) are in BOTH the iteration matrix and "
                  f"the holdout — a held-out vector cannot also be iterated on: "
                  f"{', '.join(overlap)}", file=sys.stderr)
            return 2
        cases = list(matrix) + list(hold)
    else:
        # Refuse to silently blank a recorded reservation: re-capturing a holdout
        # corpus without --holdout would zero meta.holdout and orphan the
        # held-out goldens, quietly defeating the holdout.
        try:
            prior = _read_holdout(corpus)
        except _CorpusError:
            prior = []  # unreadable prior meta: capture overwrites it cleanly below
        if prior:
            print(f"error: this corpus reserves {len(prior)} holdout vector(s) "
                  f"({', '.join(prior)}); re-run capture with --holdout covering them, "
                  f"or capture into a fresh corpus", file=sys.stderr)
            return 2
        cases = list(matrix)

    _write_meta(corpus, sort, mask_numbers, ignore_exit, holdout_names)
    norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
    nondet, timeouts, rejected, stored_names = [], [], [], set()
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
            reason = _validate_vector(case, runs, rcs, ignore_exit) if validate else None
            if reason is not None:
                rejected.append((name, reason))
                continue
            open(os.path.join(corpus, name + ".golden"), "w", encoding="utf-8").write(outs[0])
            if not ignore_exit:
                open(os.path.join(corpus, name + ".rc"), "w", encoding="utf-8").write(f"{rcs[0]}\n")
            stored_names.add(name)
    pruned = _prune_corpus(corpus, stored_names)
    print(f"captured {len(stored_names)} golden case(s) into {corpus}")
    if holdout_names:
        print(f"  ({len(holdout_names)} reserved as holdout, excluded from iteration "
              f"replay: {', '.join(holdout_names)})")
    if pruned:
        print(f"  (pruned {len(pruned)} stale golden(s) not stored this run: "
              f"{', '.join(sorted(pruned))})")
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
    matrix = D.load_matrix(matrix_path, allow_empty=True)
    # Fail closed on a present-but-unreadable reservation record — a tampered or
    # partially written corpus.meta must not silently disable the holdout guard.
    try:
        reserved = set(_read_holdout(corpus))
    except _CorpusError as e:
        print(f"error: {e}; cannot verify the holdout set — refusing replay "
              f"(re-capture the corpus)", file=sys.stderr)
        return 2

    if holdout_path and not final:
        print("error: --holdout is only run under --final (final acceptance); add "
              "--final, or drop --holdout for an iteration replay", file=sys.stderr)
        return 2

    if final:
        # Final acceptance: the ONLY mode that runs the held-back vectors.
        if not holdout_path:
            print("error: --final needs --holdout <file> (the reserved acceptance "
                  "set to run at final acceptance)", file=sys.stderr)
            return 2
        hold = D.load_matrix(holdout_path, allow_empty=True)
        hold_names = {c["name"] for c in hold}
        overlap = sorted({c["name"] for c in matrix} & hold_names)
        if overlap:
            print(f"error: {len(overlap)} case(s) are in BOTH the matrix and the "
                  f"holdout: {', '.join(overlap)}", file=sys.stderr)
            return 2
        # The gate cannot be green-lit while skipping any reserved vector.
        missing = sorted(reserved - hold_names)
        if missing:
            print(f"error: final acceptance must run every reserved holdout vector; the "
                  f"--holdout file is missing: {', '.join(missing)}", file=sys.stderr)
            return 2
        cases = [(c, False) for c in matrix] + [(c, True) for c in hold]
    else:
        # Iteration: a held-out vector must never be run here — refuse if one has
        # leaked into the iteration matrix (that would defeat the holdout).
        leaked = [c["name"] for c in matrix if c["name"] in reserved]
        if leaked:
            print(f"HOLDOUT LEAKAGE: {len(leaked)} reserved case(s) present in the "
                  f"iteration matrix and refused — a held-out vector must never be "
                  f"iterated on (run it only via --final): {', '.join(leaked)}",
                  file=sys.stderr)
            return 2
        cases = [(c, False) for c in matrix]

    fails = missing_g = holdout_run = 0
    for case, is_holdout in cases:
        status, note = _replay_case(rust, case, corpus, norm, ignore_exit)
        tag = " [holdout]" if is_holdout else ""
        if is_holdout:
            holdout_run += 1
        if status == "MISSING":
            print(f"MISSING GOLDEN: {case['name']}{tag} (run capture first)")
            missing_g += 1
        elif status == "TIMEOUT":
            print(f"[TIMEOUT] {case['name']}{tag}{note}")
            fails += 1
        elif status == "MATCH":
            print(f"[MATCH ] {case['name']}{tag}{note}")
        else:
            print(f"[FAIL  ] {case['name']}{tag}{note}")
            fails += 1

    summary = f"\n{len(cases)} cases, {fails} mismatch(es), {missing_g} missing golden"
    if final:
        summary += f" (incl. {holdout_run} holdout case(s) run at final acceptance)"
    elif reserved:
        summary += (f"; {len(reserved)} holdout case(s) reserved — excluded from "
                    f"iteration (use --final to run them)")
    print(summary)
    return 1 if (fails or missing_g) else 0


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

        # nondeterministic oracle must be flagged, not stored.
        #
        # The fixture counts its own invocations rather than drawing a random
        # number. It used to be `awk 'BEGIN{srand(); print int(rand()*1e9)}'`,
        # and awk's srand() with no argument is seeded from the clock at
        # SECOND resolution on some implementations — so on a fast runner all
        # five repeats landed in the same second, returned the identical
        # number, and this "nondeterministic" oracle looked perfectly stable.
        # capture() then correctly stored it and the check failed. Which awk is
        # installed decided whether the kit's own gate passed.
        #
        # The counter path is interpolated rather than derived from `$0`, and
        # the output written with `printf` rather than `echo … | tee`: both
        # remove a way for the fixture to go quietly CONSTANT (a `$0` that
        # resolves differently between runs gives every run a fresh counter,
        # which is the same failure wearing different clothes) and neither
        # needs a second binary on PATH.
        nd = os.path.join(d, "nd.sh")
        counter = os.path.join(d, "nd.count")
        open(nd, "w").write(
            "#!/bin/sh\n"
            "# Emit a different line every invocation, with no dependence on an\n"
            "# RNG seeding policy, the clock, or PID allocation.\n"
            f"c='{counter}'\n"
            "n=$(cat \"$c\" 2>/dev/null || echo 0)\n"
            "n=$((n + 1))\n"
            "printf '%s\\n' \"$n\" > \"$c\"\n"
            "printf 'run %s\\n' \"$n\"\n")
        os.chmod(nd, 0o755)
        ndm = os.path.join(d, "nd.json")
        open(ndm, "w").write('[{"name": "rng", "args": []}]')

        # Prove the fixture actually varies before trusting what it proves —
        # otherwise this check can only ever pass for the wrong reason
        # (LESSONS #26). A fixture that has gone constant must say so itself,
        # rather than leave the failure pointing at capture(), which is what
        # the awk version did: the detector was never broken, and the message
        # accused it anyway.
        probe = [subprocess.run([nd], capture_output=True, text=True).stdout
                 for _ in range(3)]
        check("nondeterminism fixture really does vary", len(set(probe)) == 3)

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

        # ---- hardening (adversarial review): corpus hygiene, fail-closed meta,
        # final-acceptance coverage, holdout mis-invocation ----
        # a rejected vector must leave NO stale golden behind to judge the Rust
        fail = os.path.join(d, "fail.sh")
        open(fail, "w").write("#!/bin/sh\necho oops\nexit 5\n"); os.chmod(fail, 0o755)
        stalem = os.path.join(d, "stale.json")
        open(stalem, "w").write('[{"name": "boom", "args": []}]')
        sc = os.path.join(d, "stalecorpus")
        capture(fail, stalem, sc, repeats=1, sort=False, mask_numbers=False)  # stores boom.golden
        rc = capture(fail, stalem, sc, repeats=1, sort=False, mask_numbers=False, validate=True)
        check("re-capture with --validate prunes the now-rejected vector's stale golden",
              rc == 1 and not os.path.exists(os.path.join(sc, "boom.golden")))
        # dropping a case from the suite prunes its golden too
        emptym = os.path.join(d, "empty.json")
        open(emptym, "w").write('[]')
        capture(echo, emptym, sc, repeats=1, sort=False, mask_numbers=False)
        check("a case dropped from the suite has its stale golden pruned",
              not os.path.exists(os.path.join(sc, "boom.rc")))
        # re-capturing a holdout corpus without --holdout is refused (no silent drop)
        check("re-capture without --holdout refuses to blank a recorded reservation",
              capture(echo, pub, hc, repeats=1, sort=False, mask_numbers=False) == 2)
        # final acceptance refuses an incomplete --holdout (a reserved vector missing)
        emptyhold = os.path.join(d, "emptyhold.json")
        open(emptyhold, "w").write('[]')
        check("final acceptance refuses when --holdout misses a reserved vector",
              replay(echo, pub, hc, False, False, holdout_path=emptyhold, final=True) == 2)
        # --holdout without --final is a hard error (not a silent zero-holdout pass)
        check("replay --holdout without --final errors",
              replay(echo, pub, hc, False, False, holdout_path=hold) == 2)
        # iteration replay fails CLOSED on an unreadable corpus.meta
        badmeta = os.path.join(d, "badmetacorpus")
        capture(echo, pub, badmeta, repeats=1, sort=False, mask_numbers=False, holdout_path=hold)
        open(os.path.join(badmeta, META_NAME), "w").write("{ not valid json")
        check("iteration replay refuses an unreadable corpus.meta (fail-closed)",
              replay(echo, pub, badmeta, False, False) == 2)

        # ---- C-baseline validation (--validate): admit/reject at the corpus
        # level, plus unit checks of the every-run / declared-rc / type / no-op
        # rules the adversarial review surfaced ----
        okv = os.path.join(d, "okv.json")
        open(okv, "w").write('[{"name": "ok", "args": ["hi"]}]')
        check("--validate admits a vector the C baseline passes (exit 0)",
              capture(echo, okv, os.path.join(d, "vc1"), repeats=1,
                      sort=False, mask_numbers=False, validate=True) == 0
              and os.path.exists(os.path.join(d, "vc1", "ok.golden")))
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
        r0 = ("hi\n", 0, False, "")
        check("substring assertion is checked against EVERY run, not just the first",
              _validate_vector({"name": "p", "expect_contains": "AAA"},
                               [("AAA\n", 0, False, ""), ("BBB\n", 0, False, "")], [0], False) is not None)
        check("substring assertion admits when present in every run",
              _validate_vector({"name": "p", "expect_contains": "x"},
                               [("x1\n", 0, False, ""), ("x2\n", 0, False, "")], [0], False) is None)
        check("a DECLARED expect_rc is honored even under --ignore-exit (mismatch → reject)",
              _validate_vector({"name": "e", "expect_rc": 5}, [r0], [0], True) is not None)
        check("a DECLARED expect_rc that matches is admitted under --ignore-exit",
              _validate_vector({"name": "e", "expect_rc": 5}, [("hi\n", 5, False, "")], [5], True) is None)
        check("--validate with nothing to check (ignore-exit, no assertions) fails closed",
              _validate_vector({"name": "x"}, [r0], [0], True) is not None)
        check("a non-string expect_contains is rejected, not a crash",
              _validate_vector({"name": "x", "expect_contains": 123}, [r0], [0], False) is not None)
        check("an empty expect_absent is rejected as an invalid assertion",
              _validate_vector({"name": "x", "expect_absent": ""}, [r0], [0], False) is not None)
        check("a null expect_rc is rejected (not silently defaulted)",
              _validate_vector({"name": "x", "expect_rc": None}, [r0], [0], False) is not None)
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
