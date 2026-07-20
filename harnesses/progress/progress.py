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
  ingest [--diff-json|--lib-json|--fuzz-json|--unsafe-json FILE...]
                                    auto-advance a module's gate from a harness's
                                    --json report (report stem == module name);
                                    diff_run/lib_diff→differential, diff_fuzz→
                                    fuzzed, audit_unsafe→unsafe_audited; climbs
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


def _clean_unsafe(rep):
    return isinstance(rep, dict) and rep.get("undocumented", 1) == 0


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


def cmd_ingest(path, unsafe_jsons=None, diff_jsons=None, lib_jsons=None, fuzz_jsons=None):
    """Auto-advance modules from the harnesses' own --json reports. Each report's
    file STEM must equal the module name (name reports per module, e.g.
    `diff_run.py ... --json > <mod>.json`); substring matching would let module
    `io` advance from `prio.json`. Reports map to the gate they attest:
        --diff-json / --lib-json (diff_run / lib_diff, all clean)  -> differential
        --fuzz-json  (diff_fuzz, 0 findings)                       -> fuzzed
        --unsafe-json (audit_unsafe, 0 undocumented)               -> unsafe_audited
    A gate advances a module only from its immediate predecessor, and the steps
    run in rung order, so a module with several clean reports climbs several gates
    in one ingest. (`sanitized` has no --json harness — set it manually.)"""
    state = load(path)

    def clean(files, predicate):
        stems = set()
        for jf in (files or []):
            rep = _load_report(jf)
            if rep is not None and predicate(rep):
                stems.add(_stem(jf))
        return stems

    diff_clean = clean(diff_jsons, _clean_verdicts) | clean(lib_jsons, _clean_verdicts)
    fuzz_clean = clean(fuzz_jsons, _clean_fuzz)
    unsafe_clean = clean(unsafe_jsons, _clean_unsafe)

    # (from_gate, to_gate, clean_stems), run in rung order so a module climbs as
    # far as its clean reports allow in a single ingest.
    steps = [
        ("ported", "differential", diff_clean),
        ("differential", "fuzzed", fuzz_clean),
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

        # ingest: exact-stem matching only, and only from `sanitized`
        cmd_set(p, "handles", "sanitized")
        rep = os.path.join(d, "handles.json")
        open(rep, "w").write('{"undocumented": 0}')
        stray = os.path.join(d, "sockets-extra.json")  # substring trap
        open(stray, "w").write('{"undocumented": 0}')
        cmd_set(p, "sockets", "sanitized")
        cmd_ingest(p, [rep, stray])
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
        open(dif("parser.json"), "w").write(
            '[{"name":"a","verdict":"MATCH"},{"name":"b","verdict":"DIVERGE(ledgered)"}]')
        cmd_ingest(p3, diff_jsons=[dif("parser.json")])
        check("clean diff_run report advances ported→differential",
              load(p3)["modules"]["parser"] == "differential")
        open(dif("codec.json"), "w").write('[{"name":"a","verdict":"DIVERGE"}]')
        cmd_ingest(p3, diff_jsons=[dif("codec.json")])
        check("an unexplained DIVERGE does not advance", load(p3)["modules"]["codec"] == "ported")
        open(dif("codec.json"), "w").write('[{"name":"fn","verdict":"MATCH"}]')
        cmd_ingest(p3, lib_jsons=[dif("codec.json")])
        check("clean lib_diff report advances ported→differential (library port)",
              load(p3)["modules"]["codec"] == "differential")
        # multi-rung: clean diff AND clean fuzz climb ported→fuzzed in one ingest
        open(dif("io.json"), "w").write('[{"name":"x","verdict":"MATCH"}]')
        open(fuz("io.json"), "w").write('{"iterations": 2000, "findings": []}')
        cmd_ingest(p3, diff_jsons=[dif("io.json")], fuzz_jsons=[fuz("io.json")])
        check("multi-rung: clean diff + clean fuzz climb ported→fuzzed in one ingest",
              load(p3)["modules"]["io"] == "fuzzed")
        open(fuz("parser.json"), "w").write('{"iterations": 2000, "findings": [{"fingerprint": "x"}]}')
        cmd_ingest(p3, fuzz_jsons=[fuz("parser.json")])
        check("a diff-fuzz report with findings does not advance",
              load(p3)["modules"]["parser"] == "differential")
        # a malformed report is skipped (fail-closed), never crashes the ingest
        import contextlib
        import io as _io
        open(dif("codec.json"), "w").write("{ not json")
        buf = _io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc_ig = cmd_ingest(p3, diff_jsons=[dif("codec.json")])
        check("a malformed report is skipped (no crash, no advance)",
              rc_ig == 0 and "skipping unreadable" in buf.getvalue()
              and load(p3)["modules"]["codec"] == "differential")
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
        return cmd_ingest(args.file, args.unsafe_json, args.diff_json, args.lib_json, args.fuzz_json)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
