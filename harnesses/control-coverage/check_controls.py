#!/usr/bin/env python3
"""Control-coverage — the gate above the gates: every control the kit DECLARES
must actually be INVOKED by the port's gate script.

Why (LESSONS #31): the kit had two independent guarantees and a hole between
them. `mutate_gates.py` proves each gate *detects and refuses* (its self-test
goes red when the verdict is neutralized), and `probe.py coverage` proves every
tracked module *has probes*. Neither asks the prior question: **is this control
run against the port at all?** At the cJSON port's cutover, three of the six
script-backed controls in `CLAUDE.md`'s table — `supply-chain`, `c-flaw-scan`
and `threat-model`, two of them marked "hard fail" — were never invoked by
`ports/cjson/check.sh`. All three passed the mutation sweep, because a sweep
measures a harness's self-test, not its use. The control table was prose, and no
gate read it. A control that never runs is indistinguishable from one that
always passes (LESSONS #18's 0-of-0 shape, lifted to the whole control set).

Mechanics (deliberately conservative, format-driven):
  * Read the controls doc (default `CLAUDE.md`) and take only MARKDOWN TABLE
    ROWS (lines starting with `|`) — the declared gate table, not prose that
    happens to mention a path.
  * From those rows extract runnable harness scripts: `harnesses/<...>.py|.sh`.
    A control naming a directory rather than a script (e.g. `harnesses/fuzz/`
    for cargo-fuzz) names no command to grep for and is reported as UNCHECKABLE,
    counted and listed, never silently dropped.
  * A row naming NO harness at all is reported too, by its text, as a control
    this gate cannot check. `#![forbid(unsafe_code)]` on `core` was such a row —
    the first of this kit's own table — until LESSONS #46 gave it a harness to
    name. Until LESSONS #45 the sentence above said "never
    silently dropped" and was true only of the directory case: a row with
    neither a script nor a directory fell through both regexes and vanished,
    and it was the FIRST row of the table. A parser over a human-written format
    reports what it cannot read; it does not skip it.
  * Require each extracted script to appear in the EXECUTABLE text of at least
    one gate file — comments, `name:` labels and bare YAML keys removed. A
    `# TODO: wire run_sanitizers.sh here` comment certified the sanitizer
    control as RUN until LESSONS #45; the vendored copy in the lsof line had
    fixed that and the fix never came back here.
  * Exemptions must be written down: `# control-coverage: exempt <path> -- <why>`
    in a gate file records a deliberate non-use with its reason. (An exemption
    IS a comment by design, so exemptions are read from the raw text.)

A gate file that does not exist is an error, not a skip: pointing the check at a
missing script is exactly how this would quietly pass.

Usage:
  check_controls.py --gate PORT/check.sh [--gate ...] [--controls CLAUDE.md] [--json]
  check_controls.py --self-test
Exit: 0 = every declared control is invoked (or exempted); 1 = one is not.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# Only table rows count as declarations (see module docstring).
TABLE_ROW = re.compile(r"^\s*\|")
# A runnable control: a harness script with an extension we can grep a gate for.
CONTROL_RE = re.compile(r"harnesses/[A-Za-z0-9_./-]+\.(?:py|sh)\b")
# A control naming a bare harness directory — declared but not a command.
DIRONLY_RE = re.compile(r"harnesses/[A-Za-z0-9_-]+/(?![A-Za-z0-9_.-]*\.(?:py|sh)\b)")
EXEMPT_RE = re.compile(r"control-coverage:\s*exempt\s+(\S+)\s*--\s*(.+)")
# A separator (`|---|---|`) or the header row — neither declares anything.
_SEPARATOR = re.compile(r"^\s*\|[\s:|-]*\|\s*$")


def declared_controls(controls_path):
    """(runnable, dir_only, unreadable) controls declared in the gate table.

    `unreadable` is every data row that names neither a harness script nor a
    harness directory, returned as its first cell — the control's name — so the
    caller can report it. A header row (the row directly above a `|---|`
    separator, in any number of tables) is not a declaration."""
    with open(controls_path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    headers = {i - 1 for i, ln in enumerate(lines)
               if i and _SEPARATOR.match(ln) and TABLE_ROW.match(lines[i - 1])}
    rows = [ln for i, ln in enumerate(lines)
            if TABLE_ROW.match(ln) and not _SEPARATOR.match(ln) and i not in headers]
    runnable, dir_only, unreadable = [], [], []
    for row in rows:
        found = CONTROL_RE.findall(row)
        for m in CONTROL_RE.finditer(row):
            if m.group(0) not in runnable:
                runnable.append(m.group(0))
        if not found:
            dirs = DIRONLY_RE.findall(row)
            for d in dirs:
                if d not in dir_only:
                    dir_only.append(d)
            if not dirs:
                name = row.strip().strip("|").split("|")[0].strip()
                if name and name not in unreadable:
                    unreadable.append(name)
    return runnable, dir_only, unreadable


# ---------------------------------------------------------------------------
# What counts as a gate INVOKING a control: text that configures or runs
# something. Searching the raw file answers a different question — whether the
# file SAYS the name — and the two come apart exactly when it matters: a gate
# that has not wired a control yet is the gate most likely to carry a comment
# saying it should. Excluded, because none of them runs anything: comments,
# `name:` values (a step LABELLED "sanitizers" runs no sanitizer) and bare YAML
# keys (a job called `miri:` is a label too). Deliberately conservative: a
# `run:` script line that happens to look like `name: x` is dropped as well,
# which can only cause a false NEGATIVE — the safe direction for a control whose
# failure mode was accepting too little. Ported from the lsof line, where it
# lives in `check_ledgers.py` beside the ledger check that first needed it.
_KEYVAL = re.compile(r"^\s*-?\s*([A-Za-z_][\w.-]*)\s*:\s*(.*)$")
_BLOCK_SCALAR = {"|", ">", "|-", ">-", "|+", ">+"}


def _strip_comment(line):
    """Drop an end-of-line `#` comment. A `#` inside quotes is not a comment,
    and neither is one glued to a word (`$#`, `${#arr[@]}`)."""
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            out.append(ch)
        elif ch == "#" and (not out or out[-1].isspace()):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def executable_text(text):
    """The parts of a gate file that configure or run something."""
    keep = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        m = _KEYVAL.match(line)
        if not m:
            keep.append(line)          # a command, a block-scalar body, a list item
            continue
        key, val = m.group(1), m.group(2).strip()
        if key.lower() == "name":
            continue                   # a human-readable label
        if not val or val in _BLOCK_SCALAR:
            continue                   # a bare key, or a block-scalar introducer
        keep.append(val)
    return "\n".join(keep)


def control_is_wired(control, gate_texts):
    """THE VERDICT (kept as one predicate so gate-mutation can neutralize it and
    the self-test's negative fixture must then go red — LESSONS #25)."""
    base = os.path.basename(control)
    return any((control in t) or (base in t)
               for t in (executable_text(g) for g in gate_texts))


def exemptions(gate_texts):
    out = {}
    for text in gate_texts:
        for m in EXEMPT_RE.finditer(text):
            out[m.group(1)] = m.group(2).strip()
    return out


def check(controls_path, gate_paths, as_json=False):
    if not os.path.isfile(controls_path):
        print(f"error: controls doc not found: {controls_path}", file=sys.stderr)
        return 2
    missing_gates = [g for g in gate_paths if not os.path.isfile(g)]
    if missing_gates:
        # Fail closed: a gate file that isn't there cannot be shown to run anything.
        for g in missing_gates:
            print(f"error: gate script not found: {g}", file=sys.stderr)
        return 2

    texts = []
    for g in gate_paths:
        with open(g, encoding="utf-8") as fh:
            texts.append(fh.read())

    runnable, dir_only, unreadable = declared_controls(controls_path)
    if not runnable:
        # 0-of-0 proves nothing and must not pass (LESSONS #18).
        print(f"error: no runnable controls found in {controls_path}'s table — "
              "a coverage check over zero controls proves nothing",
              file=sys.stderr)
        return 2

    exempt = exemptions(texts)
    wired, unwired, skipped = [], [], []
    for c in runnable:
        if control_is_wired(c, texts):
            wired.append(c)
        elif c in exempt:
            skipped.append((c, exempt[c]))
        else:
            unwired.append(c)

    if as_json:
        json.dump({"tool": "control-coverage", "controls": runnable,
                   "wired": wired, "unwired": unwired,
                   "exempt": [{"control": c, "why": w} for c, w in skipped],
                   "uncheckable": dir_only, "not_a_harness": unreadable,
                   "gates": gate_paths, "ok": not unwired}, sys.stdout, indent=1)
        print()
    else:
        for c in wired:
            print(f"  RUN      {c}")
        for c, why in skipped:
            print(f"  EXEMPT   {c}  ({why})")
        for c in unwired:
            print(f"  NOT RUN  {c}", file=sys.stderr)
        for d in dir_only:
            print(f"  (uncheckable, names no script: {d})")
        for r in unreadable:
            print(f"  (uncheckable, names no harness — enforced by nothing here: {r})")
        if unwired:
            print(f"\ncontrol-coverage FAILED: {len(unwired)} declared control(s) "
                  f"never invoked by {', '.join(gate_paths)}.\n"
                  "A control that never runs cannot be told from one that always "
                  "passes. Wire it into the gate, or record\n"
                  "  # control-coverage: exempt <path> -- <why>\n"
                  "in the gate with the reason.", file=sys.stderr)
        else:
            print(f"\ncontrol coverage: {len(wired)} control(s) invoked, "
                  f"{len(skipped)} exempted, "
                  f"{len(dir_only) + len(unreadable)} uncheckable")
    return 1 if unwired else 0


def _self_test():
    import tempfile
    ok = True

    def check_case(label, cond):
        nonlocal ok
        print(f"{'PASS' if cond else 'FAIL'}  {label}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        controls = os.path.join(d, "CLAUDE.md")
        with open(controls, "w", encoding="utf-8") as fh:
            fh.write("prose mentioning harnesses/notatable/ignored.py must not count\n\n"
                     "| Control | Command |\n|---|---|\n"
                     "| a | `harnesses/alpha/a.py` |\n"
                     "| b | `harnesses/beta/b.sh` |\n"
                     "| c | `harnesses/fuzz/` (cargo-fuzz) |\n"
                     "| d | `#![forbid(unsafe_code)]` on `core` |\n")

        runnable, dir_only, unreadable = declared_controls(controls)
        check_case("table rows parsed, prose ignored",
                   runnable == ["harnesses/alpha/a.py", "harnesses/beta/b.sh"])
        check_case("a directory-only control is reported, not dropped",
                   dir_only == ["harnesses/fuzz/"])
        # LESSONS #45: a row naming NO harness fell through both regexes and
        # vanished — the docstring's "never silently dropped" was true of the
        # directory case only. The header row must not be mistaken for one.
        check_case("a row naming no harness is REPORTED, not dropped (header excluded)",
                   unreadable == ["d"])
        two = os.path.join(d, "two-tables.md")
        with open(two, "w", encoding="utf-8") as fh:
            fh.write("| Control | Command |\n|---|---|\n| a | `harnesses/alpha/a.py` |\n\n"
                     "| Other | Table |\n|:--|--:|\n| x | `harnesses/beta/b.sh` |\n")
        check_case("every table's header is excluded, not just the first",
                   declared_controls(two)[2] == [])

        full = os.path.join(d, "full.sh")
        with open(full, "w", encoding="utf-8") as fh:
            fh.write("python3 harnesses/alpha/a.py\nbash harnesses/beta/b.sh\n")
        check_case("a gate running every control passes", check(controls, [full]) == 0)

        # NEGATIVE FIXTURE: the failure this gate exists to catch.
        partial = os.path.join(d, "partial.sh")
        with open(partial, "w", encoding="utf-8") as fh:
            fh.write("python3 harnesses/alpha/a.py\n")
        check_case("a gate MISSING a control fails", check(controls, [partial]) == 1)

        # the crown verdict must be what decides it (gate-mutation target)
        check_case("verdict predicate refuses an unwired control",
                   control_is_wired("harnesses/beta/b.sh", ["python3 harnesses/alpha/a.py"]) is False)

        # LESSONS #45: a COMMENT is not an invocation. The gate most likely to
        # carry "wire b.sh here" is the one that has not wired it yet. Also a
        # step's `name:` label and a bare job key — neither runs anything. And
        # the stripper must not eat bash's `$#` or `${#arr[@]}`.
        commented = os.path.join(d, "commented.sh")
        with open(commented, "w", encoding="utf-8") as fh:
            fh.write("python3 harnesses/alpha/a.py\n"
                     "# TODO: wire harnesses/beta/b.sh here eventually\n")
        check_case("a control named only in a COMMENT is NOT RUN",
                   check(controls, [commented]) == 1)
        check_case("a control named only in a `name:` label or job key is NOT RUN",
                   not control_is_wired("harnesses/beta/b.sh",
                                        ["jobs:\n  b.sh:\n    steps:\n"
                                         "      - name: run b.sh\n"
                                         "        run: echo nothing\n"]))
        check_case("a real invocation after `${#arr[@]}` on the same line still counts",
                   control_is_wired("harnesses/beta/b.sh",
                                    ['n=${#arr[@]} bash harnesses/beta/b.sh "$n"']))

        exempted = os.path.join(d, "exempt.sh")
        with open(exempted, "w", encoding="utf-8") as fh:
            fh.write("python3 harnesses/alpha/a.py\n"
                     "# control-coverage: exempt harnesses/beta/b.sh -- no deps to audit\n")
        check_case("a written-down exemption passes", check(controls, [exempted]) == 0)

        # 0-of-0 must not pass (LESSONS #18)
        empty = os.path.join(d, "empty.md")
        with open(empty, "w", encoding="utf-8") as fh:
            fh.write("no table here\n")
        check_case("a controls doc with no table fails (0-of-0)",
                   check(empty, [full]) == 2)

        # a missing gate file is an error, not a silent pass
        check_case("a missing gate script fails closed",
                   check(controls, [os.path.join(d, "nope.sh")]) == 2)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--controls", default="CLAUDE.md")
    ap.add_argument("--gate", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.gate:
        print("error: give at least one --gate, or --self-test", file=sys.stderr)
        return 2
    return check(a.controls, a.gate, a.json)


if __name__ == "__main__":
    sys.exit(main())
