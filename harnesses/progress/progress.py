#!/usr/bin/env python3
"""Progress tracker — a per-module status table so any session (human or agent)
orients in seconds: which modules are done, which are mid-port, what gate each is
stuck at. State lives in a human-editable JSON file (default: progress.json).

The gates mirror PLAYBOOK.md Phase 4, in order:
    ported -> differential -> fuzzed -> sanitized -> unsafe_audited
A module's status is the highest gate it has cleared. "Done" = unsafe_audited.

  init   --modules a,b,c            seed a fresh table (all not_started)
  set    MODULE GATE [--add]        mark MODULE as having cleared GATE
                                    (unknown modules error unless --add)
  show   [--json]                   render the table
  ingest [--diff-json|--lib-json|--fuzz-json|--sanitize-json|--unsafe-json FILE...]
                                    auto-advance a module's gate from a harness's
                                    --json report (report stem == module name);
                                    diff_run/lib_diff→differential, diff_fuzz→
                                    fuzzed, run_sanitizers→sanitized,
                                    audit_unsafe→unsafe_audited; climbs
                                    multiple gates in one call

Usage: progress.py [--file progress.json] {init,set,show,ingest} ...
       (--file may be given before or after the subcommand)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

GATES = ["not_started", "ported", "differential", "fuzzed", "sanitized", "unsafe_audited"]
DONE = "unsafe_audited"


def load(path):
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {"modules": {}}


def save(path, state):
    json.dump(state, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)


def cmd_init(path, modules):
    state = {"modules": {m: "not_started" for m in modules}}
    save(path, state)
    print(f"seeded {len(modules)} module(s) into {path}")
    return 0


def cmd_set(path, module, gate, add=False):
    if gate not in GATES:
        print(f"error: gate must be one of {', '.join(GATES)}", file=sys.stderr)
        return 2
    state = load(path)
    # A typo must not silently mint a new module row (which then undercounts
    # real progress forever). Adding a genuinely new module is explicit: --add.
    if module not in state["modules"] and not add:
        known = ", ".join(sorted(state["modules"])) or "(none)"
        print(f"error: unknown module '{module}' (known: {known}); "
              f"pass --add to create it", file=sys.stderr)
        return 2
    state["modules"][module] = gate
    save(path, state)
    print(f"{module} -> {gate}")
    return 0


def render(state):
    mods = state["modules"]
    if not mods:
        return "(no modules; run `progress.py init --modules a,b,c`)"
    width = max((len(m) for m in mods), default=6)
    cols = GATES[1:]  # skip not_started in the tick columns
    head = "module".ljust(width) + "  " + "  ".join(c[:5].center(5) for c in cols) + "   status"
    rows = [head, "-" * len(head)]
    for m in sorted(mods):
        cur = mods[m]
        ci = GATES.index(cur) if cur in GATES else 0
        ticks = []
        for g in cols:
            ticks.append(" [x] " if ci >= GATES.index(g) else " [ ] ")
        status = "DONE" if cur == DONE else cur
        rows.append(m.ljust(width) + "  " + "  ".join(t[:5] for t in ticks) + "   " + status)
    done = sum(1 for v in mods.values() if v == DONE)
    rows.append("")
    rows.append(f"{done}/{len(mods)} modules fully gated (unsafe-audited).")
    return "\n".join(rows)


def cmd_show(path, as_json):
    state = load(path)
    if as_json:
        print(json.dumps(state, indent=2, sort_keys=True))
    else:
        print(render(state))
    return 0


def _stem(jf):
    return os.path.splitext(os.path.basename(jf))[0]


def _load_report(jf):
    """Read a harness --json report; a missing/malformed one is SKIPPED with a
    warning (never advances a gate, never crashes the ingest) — fail closed."""
    try:
        return json.load(open(jf, encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"warn: skipping unreadable report {jf}: {e}", file=sys.stderr)
        return None


def _repo_head():
    """HEAD sha of the repo we're ingesting in, or None outside a checkout."""
    import subprocess
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                           text=True, timeout=10)
        return p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else None
    except (OSError, subprocess.SubprocessError):
        return None


def _split_report(rep):
    """(provenance-stamp-or-None, payload). Stamped diff_run/lib_diff reports are
    wrapped `{"provenance": .., "results": [..]}`; stamped diff_fuzz/audit_unsafe
    reports are dicts with a `provenance` key; a bare list is a legacy unstamped
    report."""
    if isinstance(rep, dict) and "results" in rep:
        return rep.get("provenance"), rep["results"]
    if isinstance(rep, dict):
        return rep.get("provenance"), rep
    return None, rep


def _provenance_ok(stamp, jf, max_age_min, allow_unstamped, repo_sha):
    """Verify a report's run-provenance against the tree (RETROSPECTIVE-kit-audit
    §6 item 8): a shape-valid report may still be STALE — generated before the
    code changed — or hand-authored. sha comparison is primary (report's commit
    must BE the tree's commit); when either side has no sha, the stamp's age is
    the fallback. Unstamped legacy reports are refused unless --allow-unstamped.
    Returns True to ingest; on False the report is skipped with a warning (fail
    closed: skipping never advances a gate)."""
    import datetime
    if not isinstance(stamp, dict):
        if allow_unstamped:
            print(f"warn: {jf}: unstamped legacy report ingested via "
                  f"--allow-unstamped; re-run the harness to stamp it", file=sys.stderr)
            return True
        print(f"warn: skipping {jf}: no provenance stamp — a report must prove "
              f"which tree it came from (re-run the harness with --json, or pass "
              f"--allow-unstamped to ingest legacy reports)", file=sys.stderr)
        return False
    rep_sha = stamp.get("git_sha")
    if rep_sha and repo_sha:
        if rep_sha != repo_sha:
            print(f"warn: skipping {jf}: STALE report — generated at commit "
                  f"{rep_sha[:12]}, tree is at {repo_sha[:12]}; re-run the harness "
                  f"against the current code", file=sys.stderr)
            return False
        return True
    # no sha on one side (outside a checkout) → the stamp's age decides
    try:
        gen = datetime.datetime.fromisoformat(stamp["generated_at"])
        age_min = (datetime.datetime.now(datetime.timezone.utc) - gen).total_seconds() / 60
    except (KeyError, TypeError, ValueError):
        print(f"warn: skipping {jf}: unreadable provenance timestamp (fail closed)",
              file=sys.stderr)
        return False
    if age_min > max_age_min:
        print(f"warn: skipping {jf}: report is {age_min:.0f} min old "
              f"(> --max-age-min {max_age_min}) and carries no git sha to verify — "
              f"re-run the harness", file=sys.stderr)
        return False
    return True


def _clean_unsafe(rep):
    # audit_unsafe.py --json: zero undocumented blocks AND at least one block
    # actually audited. A 0-of-0 report means the gate found NOTHING to check
    # (a forbid-unsafe crate, or the wrong path) — that is not evidence of a
    # clean unsafe surface and must not advance the gate (LESSONS #18).
    # `blocks_found` is absent in pre-#18 reports; those fall back to the old
    # rule rather than silently failing an existing port's ingest.
    if not isinstance(rep, dict) or rep.get("undocumented", 1) != 0:
        return False
    return rep.get("blocks_found", 1) > 0


def _clean_verdicts(rep):
    # diff_run.py / lib_diff.py --json: a NON-EMPTY list of verdicts, every one a
    # MATCH or a ledgered divergence (no DIVERGE/CRASH/TIMEOUT/ERROR). An empty
    # report proves nothing and must not advance a gate.
    return (isinstance(rep, list) and len(rep) > 0
            and all(isinstance(r, dict) and r.get("verdict") in ("MATCH", "DIVERGE(ledgered)")
                    for r in rep))


def _clean_fuzz(rep):
    # diff_fuzz.py --json: it actually ran (iterations > 0) and found no divergence.
    return (isinstance(rep, dict) and rep.get("iterations", 0) > 0
            and rep.get("findings", [None]) == [])


def _clean_sanitize(rep):
    # run_sanitizers.sh --json: a checker actually RAN (non-empty `modes_run`)
    # and exited clean (`rc == 0`).
    #
    # Why this predicate exists at all (LESSONS #24): `sanitized` used to be the
    # one rung with no machine-checked evidence — every other gate advances from
    # a provenance-stamped report, but this one was set by hand from the port's
    # own check script. Nothing ever un-set it, and progress.json is committed,
    # so the claim outlived its proof: a port read fully-gated in a container
    # where the sanitizer was not even installed. An empty `modes_run` is the
    # 0-of-0 pass again (LESSONS #18/#22) — a SKIP is not a clean run.
    if not isinstance(rep, dict) or rep.get("rc", 1) != 0:
        return False
    modes = rep.get("modes_run")
    return isinstance(modes, list) and len(modes) > 0


def cmd_ingest(path, unsafe_jsons=None, diff_jsons=None, lib_jsons=None, fuzz_jsons=None,
               sanitize_jsons=None, allow_unstamped=False, max_age_min=1440,
               repo_sha="auto"):
    """Auto-advance modules from the harnesses' own --json reports. Each report's
    file STEM must equal the module name (name reports per module, e.g.
    `diff_run.py ... --json > <mod>.json`); substring matching would let module
    `io` advance from `prio.json`. Reports map to the gate they attest:
        --diff-json / --lib-json (diff_run / lib_diff, all clean)  -> differential
        --fuzz-json  (diff_fuzz, 0 findings)                       -> fuzzed
        --sanitize-json (run_sanitizers.sh, a mode ran + rc 0)      -> sanitized
        --unsafe-json (audit_unsafe, 0 undocumented)               -> unsafe_audited
    A gate advances a module only from its immediate predecessor, and the steps
    run in rung order, so a module with several clean reports climbs several gates
    in one ingest. Every rung now advances from a stamped report; `sanitized` was
    the last hand-set one (LESSONS #24).

    Every report must also clear PROVENANCE (RETROSPECTIVE-kit-audit §6 item 8):
    its stamp's git sha must match the tree's HEAD (age is the fallback when a
    sha is unavailable; `--max-age-min`, default 1440). A shape-valid report is
    not proof of a clean run — it may predate the code it vouches for. Unstamped
    legacy reports need `--allow-unstamped`."""
    state = load(path)
    if repo_sha == "auto":
        repo_sha = _repo_head()

    def clean(files, predicate):
        stems = set()
        for jf in (files or []):
            rep = _load_report(jf)
            if rep is None:
                continue
            stamp, payload = _split_report(rep)
            if not _provenance_ok(stamp, jf, max_age_min, allow_unstamped, repo_sha):
                continue
            if predicate(payload):
                stems.add(_stem(jf))
        return stems

    diff_clean = clean(diff_jsons, _clean_verdicts) | clean(lib_jsons, _clean_verdicts)
    fuzz_clean = clean(fuzz_jsons, _clean_fuzz)
    unsafe_clean = clean(unsafe_jsons, _clean_unsafe)
    sanitize_clean = clean(sanitize_jsons, _clean_sanitize)

    # (from_gate, to_gate, clean_stems), run in rung order so a module climbs as
    # far as its clean reports allow in a single ingest.
    steps = [
        ("ported", "differential", diff_clean),
        ("differential", "fuzzed", fuzz_clean),
        ("fuzzed", "sanitized", sanitize_clean),
        ("sanitized", "unsafe_audited", unsafe_clean),
    ]
    advanced = []
    for frm, to, ok in steps:
        for m in state["modules"]:
            if state["modules"][m] == frm and m in ok:
                state["modules"][m] = to
                advanced.append(f"{m}->{to}")
    save(path, state)
    print("ingest: advanced " + (", ".join(sorted(advanced)) if advanced else "nothing"))
    return 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "progress.json")
        cmd_init(p, ["process", "sockets", "handles"])
        st = load(p)
        check("init seeds 3 not_started modules",
              len(st["modules"]) == 3 and all(v == "not_started" for v in st["modules"].values()))
        cmd_set(p, "process", "unsafe_audited")
        cmd_set(p, "sockets", "differential")
        st = load(p)
        check("set advances a module to DONE", st["modules"]["process"] == "unsafe_audited")
        out = render(st)
        check("render marks the done module", "DONE" in out)
        check("render shows partial progress", "differential" in out)
        check("render counts 1/3 fully gated", "1/3 modules fully gated" in out)

        # The CLI accepts --file on either side of the subcommand (the
        # docstring's paste-able order used to be rejected).
        p2 = os.path.join(d, "p2.json")
        check("--file before the subcommand works",
              main(["--file", p2, "init", "--modules", "a"]) == 0)
        check("--file after the subcommand works",
              main(["set", "a", "ported", "--file", p2]) == 0)
        check("both orders hit the same state file",
              load(p2)["modules"]["a"] == "ported")

        # a typo'd module errors instead of silently minting a row; --add opts in
        check("unknown module rejected", cmd_set(p2, "procss", "ported") == 2)
        check("typo did not create a row", "procss" not in load(p2)["modules"])
        check("--add creates a new module deliberately",
              cmd_set(p2, "newmod", "ported", add=True) == 0
              and load(p2)["modules"]["newmod"] == "ported")

        # Stamped-fixture helpers: every ingest fixture carries provenance so
        # these checks pin the PREDICATES; the provenance layer has its own
        # checks below. repo_sha is passed explicitly everywhere so the tests
        # are deterministic inside and outside a git checkout.
        import datetime
        import json as _json

        def _prov(sha=None, age_min=0.0):
            gen = (datetime.datetime.now(datetime.timezone.utc)
                   - datetime.timedelta(minutes=age_min)).isoformat(timespec="seconds")
            return {"harness": "t", "generated_at": gen, "git_sha": sha}

        def wdict(path_, payload, sha=None, age_min=0.0):
            payload = dict(payload, provenance=_prov(sha, age_min))
            open(path_, "w").write(_json.dumps(payload))

        def wlist(path_, results, sha=None, age_min=0.0):
            open(path_, "w").write(_json.dumps(
                {"provenance": _prov(sha, age_min), "results": results}))

        # ingest: exact-stem matching only, and only from `sanitized`
        cmd_set(p, "handles", "sanitized")
        rep = os.path.join(d, "handles.json")
        wdict(rep, {"undocumented": 0})
        stray = os.path.join(d, "sockets-extra.json")  # substring trap
        wdict(stray, {"undocumented": 0})
        cmd_set(p, "sockets", "sanitized")
        cmd_ingest(p, [rep, stray], repo_sha=None)
        st = load(p)
        check("ingest advances the exact-stem module",
              st["modules"]["handles"] == "unsafe_audited")
        check("a substring-named report advances nothing",
              st["modules"]["sockets"] == "sanitized")

        # extended ingest (P2 #9): diff_run/lib_diff --json → differential,
        # diff_fuzz → fuzzed; each still exact-stem and fail-closed.
        p3 = os.path.join(d, "p3.json")
        cmd_init(p3, ["parser", "codec", "io"])
        for m in ("parser", "codec", "io"):
            cmd_set(p3, m, "ported")
        os.makedirs(os.path.join(d, "dif"))
        os.makedirs(os.path.join(d, "fuz"))
        dif = lambda n: os.path.join(d, "dif", n)
        fuz = lambda n: os.path.join(d, "fuz", n)
        wlist(dif("parser.json"),
              [{"name": "a", "verdict": "MATCH"}, {"name": "b", "verdict": "DIVERGE(ledgered)"}])
        cmd_ingest(p3, diff_jsons=[dif("parser.json")], repo_sha=None)
        check("clean diff_run report advances ported→differential",
              load(p3)["modules"]["parser"] == "differential")
        wlist(dif("codec.json"), [{"name": "a", "verdict": "DIVERGE"}])
        cmd_ingest(p3, diff_jsons=[dif("codec.json")], repo_sha=None)
        check("an unexplained DIVERGE does not advance", load(p3)["modules"]["codec"] == "ported")
        # "An empty report proves nothing and must not advance a gate" — the
        # predicate's own comment, held by no fixture until LESSONS #48/#50's
        # decision sweep forced its length test off. Nor does a report whose
        # items are not verdict objects.
        wlist(dif("codec.json"), [])
        cmd_ingest(p3, diff_jsons=[dif("codec.json")], repo_sha=None)
        check("an EMPTY diff report does not advance (0-of-0 proves nothing)",
              load(p3)["modules"]["codec"] == "ported")
        check("a report that is not a list of verdict objects is not clean",
              _clean_verdicts(None) is False and _clean_verdicts(7) is False
              and _clean_verdicts(["MATCH"]) is False)
        wlist(dif("codec.json"), [{"name": "fn", "verdict": "MATCH"}])
        cmd_ingest(p3, lib_jsons=[dif("codec.json")], repo_sha=None)
        check("clean lib_diff report advances ported→differential (library port)",
              load(p3)["modules"]["codec"] == "differential")
        # multi-rung: clean diff AND clean fuzz climb ported→fuzzed in one ingest
        wlist(dif("io.json"), [{"name": "x", "verdict": "MATCH"}])
        wdict(fuz("io.json"), {"iterations": 2000, "findings": []})
        cmd_ingest(p3, diff_jsons=[dif("io.json")], fuzz_jsons=[fuz("io.json")],
                   repo_sha=None)
        check("multi-rung: clean diff + clean fuzz climb ported→fuzzed in one ingest",
              load(p3)["modules"]["io"] == "fuzzed")
        wdict(fuz("parser.json"), {"iterations": 2000, "findings": [{"fingerprint": "x"}]})
        cmd_ingest(p3, fuzz_jsons=[fuz("parser.json")], repo_sha=None)
        check("a diff-fuzz report with findings does not advance",
              load(p3)["modules"]["parser"] == "differential")

        # LESSONS #24: `sanitized` advances from a run_sanitizers.sh report like
        # every other rung, instead of being hand-set and immortal. Its own
        # fixture file — these rows must not perturb the tests above or below.
        ps = os.path.join(d, "ps.json")
        cmd_init(ps, ["clean", "skipped", "failed"])
        for m in ("clean", "skipped", "failed"):
            cmd_set(ps, m, "fuzzed")
        os.makedirs(os.path.join(d, "san"))
        san = lambda n: os.path.join(d, "san", n)
        wdict(san("clean.json"), {"mode": "all", "modes_run": ["miri", "address"], "rc": 0})
        cmd_ingest(ps, sanitize_jsons=[san("clean.json")], repo_sha=None)
        check("a clean sanitizer report advances fuzzed→sanitized",
              load(ps)["modules"]["clean"] == "sanitized")
        # THE fixture: a SKIP (nothing ran) must NOT advance the rung, even at
        # rc=0 — the 0-of-0 pass this whole rung was rebuilt to refuse.
        wdict(san("skipped.json"), {"mode": "all", "modes_run": [], "rc": 0})
        cmd_ingest(ps, sanitize_jsons=[san("skipped.json")], repo_sha=None)
        check("a sanitizer report where NOTHING ran does not advance (LESSONS #24)",
              load(ps)["modules"]["skipped"] == "fuzzed")
        wdict(san("failed.json"), {"mode": "all", "modes_run": ["miri"], "rc": 1})
        cmd_ingest(ps, sanitize_jsons=[san("failed.json")], repo_sha=None)
        check("a sanitizer report with rc!=0 does not advance",
              load(ps)["modules"]["failed"] == "fuzzed")
        # a malformed report is skipped (fail-closed), never crashes the ingest
        import contextlib
        import io as _io
        open(dif("codec.json"), "w").write("{ not json")
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc_ig = cmd_ingest(p3, diff_jsons=[dif("codec.json")], repo_sha=None)
        check("a malformed report is skipped (no crash, no advance)",
              rc_ig == 0 and "skipping unreadable" in buf.getvalue()
              and load(p3)["modules"]["codec"] == "differential")

        # LESSONS #18: a 0-of-0 unsafe report is NOT evidence — it must not
        # advance `unsafe_audited`. (A pre-#18 report without the key still
        # advances, so an existing port's ingest doesn't break.)
        p5 = os.path.join(d, "p5.json")
        cmd_init(p5, ["m"])
        cmd_set(p5, "m", "sanitized")
        wdict(pv5 := os.path.join(d, "m.json"),
              {"undocumented": 0, "blocks_found": 0})
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            cmd_ingest(p5, [pv5], repo_sha=None)
        check("a 0-of-0 unsafe report does NOT advance unsafe_audited",
              load(p5)["modules"]["m"] == "sanitized")
        wdict(pv5, {"undocumented": 0, "blocks_found": 33})
        cmd_ingest(p5, [pv5], repo_sha=None)
        check("an unsafe report that audited real blocks DOES advance",
              load(p5)["modules"]["m"] == "unsafe_audited")

        # PROVENANCE (RETROSPECTIVE-kit-audit §6 item 8): a shape-valid report is
        # not proof of a clean run. All repo_sha values are explicit so these are
        # deterministic in and out of a git checkout.
        SHA_A, SHA_B = "a" * 40, "b" * 40
        p4 = os.path.join(d, "p4.json")
        cmd_init(p4, ["mod"])
        cmd_set(p4, "mod", "ported")
        pv = lambda n: os.path.join(d, n)

        # unstamped legacy report: refused by default, ingested with the opt-in
        open(pv("mod.json"), "w").write('[{"name":"x","verdict":"MATCH"}]')
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            cmd_ingest(p4, diff_jsons=[pv("mod.json")], repo_sha=None)
        check("an unstamped report is refused by default (fail closed)",
              load(p4)["modules"]["mod"] == "ported"
              and "no provenance stamp" in buf.getvalue())
        with contextlib.redirect_stderr(_io.StringIO()):
            cmd_ingest(p4, diff_jsons=[pv("mod.json")], repo_sha=None,
                       allow_unstamped=True)
        check("--allow-unstamped ingests the legacy report",
              load(p4)["modules"]["mod"] == "differential")

        # sha match advances; sha MISMATCH (stale report) is refused
        cmd_set(p4, "mod", "ported")
        wlist(pv("mod.json"), [{"name": "x", "verdict": "MATCH"}], sha=SHA_A)
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            cmd_ingest(p4, diff_jsons=[pv("mod.json")], repo_sha=SHA_B)
        check("a report from a DIFFERENT commit is refused as stale",
              load(p4)["modules"]["mod"] == "ported" and "STALE report" in buf.getvalue())
        cmd_ingest(p4, diff_jsons=[pv("mod.json")], repo_sha=SHA_A)
        check("a report from THIS commit advances", load(p4)["modules"]["mod"] == "differential")

        # no comparable sha → age decides: too old refused, fresh accepted
        cmd_set(p4, "mod", "ported")
        wlist(pv("mod.json"), [{"name": "x", "verdict": "MATCH"}], age_min=2000)
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            cmd_ingest(p4, diff_jsons=[pv("mod.json")], repo_sha=None)
        check("an over-age unverifiable report is refused",
              load(p4)["modules"]["mod"] == "ported" and "min old" in buf.getvalue())
        wlist(pv("mod.json"), [{"name": "x", "verdict": "MATCH"}], age_min=1)
        cmd_ingest(p4, diff_jsons=[pv("mod.json")], repo_sha=None)
        check("a fresh unverifiable report is accepted via the age fallback",
              load(p4)["modules"]["mod"] == "differential")

        # a stamp with an unreadable timestamp fails closed
        cmd_set(p4, "mod", "ported")
        open(pv("mod.json"), "w").write(
            '{"provenance": {"harness": "t", "generated_at": "not-a-date"}, '
            '"results": [{"name":"x","verdict":"MATCH"}]}')
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            cmd_ingest(p4, diff_jsons=[pv("mod.json")], repo_sha=None)
        check("an unreadable provenance timestamp fails closed",
              load(p4)["modules"]["mod"] == "ported"
              and "unreadable provenance timestamp" in buf.getvalue())
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="progress.json")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    pi = sub.add_parser("init"); pi.add_argument("--modules", required=True, help="comma-separated")
    ps = sub.add_parser("set"); ps.add_argument("module"); ps.add_argument("gate")
    ps.add_argument("--add", action="store_true", help="allow creating a module not seeded by init")
    psh = sub.add_parser("show"); psh.add_argument("--json", action="store_true")
    pg = sub.add_parser("ingest")
    pg.add_argument("--unsafe-json", nargs="+", default=[], help="audit_unsafe.py --json → unsafe_audited")
    pg.add_argument("--diff-json", nargs="+", default=[], help="diff_run.py --json → differential")
    pg.add_argument("--lib-json", nargs="+", default=[], help="lib_diff.py --json → differential")
    pg.add_argument("--fuzz-json", nargs="+", default=[], help="diff_fuzz.py --json → fuzzed")
    pg.add_argument("--sanitize-json", nargs="+", default=[],
                    help="run_sanitizers.sh --json → sanitized")
    pg.add_argument("--allow-unstamped", action="store_true",
                    help="ingest legacy reports that carry no provenance stamp")
    pg.add_argument("--max-age-min", type=float, default=1440,
                    help="max stamp age (minutes) when no git sha is comparable (default 1440)")
    # Accept --file AFTER the subcommand too (the natural paste order, and the
    # order the docstring shows). SUPPRESS keeps a pre-subcommand --file (or
    # the top-level default) intact when the flag isn't repeated here.
    for sp in (pi, ps, psh, pg):
        sp.add_argument("--file", default=argparse.SUPPRESS,
                        help="state file (default progress.json)")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.cmd == "init":
        return cmd_init(args.file, [m.strip() for m in args.modules.split(",") if m.strip()])
    if args.cmd == "set":
        return cmd_set(args.file, args.module, args.gate, args.add)
    if args.cmd == "show":
        return cmd_show(args.file, args.json)
    if args.cmd == "ingest":
        return cmd_ingest(args.file, args.unsafe_json, args.diff_json, args.lib_json,
                          args.fuzz_json, sanitize_jsons=args.sanitize_json,
                          allow_unstamped=args.allow_unstamped,
                          max_age_min=args.max_age_min)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
