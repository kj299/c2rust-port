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
  ingest --unsafe-json FILE ...     auto-advance from a harness's --json output
                                    (report stem must equal the module name)

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


def cmd_ingest(path, unsafe_jsons):
    """Advance modules to `unsafe_audited` when an audit_unsafe.py --json report
    shows zero undocumented findings. Conservative: only ticks the final gate,
    only for modules already at `sanitized`, and only when the report file's
    STEM exactly equals the module name — name reports per module, e.g.
    `audit_unsafe.py crates/<mod> --json > <mod>.json`. (Substring matching
    would let module `io` advance from `prio.json`.)"""
    state = load(path)
    clean_stems = set()
    for jf in unsafe_jsons:
        rep = json.load(open(jf, encoding="utf-8"))
        if rep.get("undocumented", 1) == 0:
            clean_stems.add(os.path.splitext(os.path.basename(jf))[0])
    advanced = []
    for m in state["modules"]:
        if state["modules"][m] == "sanitized" and m in clean_stems:
            state["modules"][m] = "unsafe_audited"
            advanced.append(m)
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
    pg = sub.add_parser("ingest"); pg.add_argument("--unsafe-json", nargs="+", default=[])
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
        return cmd_ingest(args.file, args.unsafe_json)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
