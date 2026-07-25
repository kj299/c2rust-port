#!/usr/bin/env python3
"""Gate-mutation harness — break each gate's verdict on purpose and PROVE the
suite goes red. The standing "failure the kit still would not prevent" since
retro #1 (RETROSPECTIVE-kit-v1.md §5 item 2), sharpened by LESSONS #13/#14: the
kit's fail-open holes (LEDGER-STALE, the wrapped-path skip, the fenced-block
harvest) were all gates that PASSED while checking nothing, each found by a
human probing by hand. This harness makes that probe mechanical.

For every gate in MUTATIONS, in a scratch copy of the kit:
  1. neutralize that gate's verdict logic (one surgical, table-driven edit —
     e.g. `is_match = True`, `return []`, `if False:`), then
  2. run the gate's own self-test and REQUIRE it to fail.
A self-test that stays green over a neutralized verdict is a survivor: the
"pinned regression suite" for that gate is theater, and this harness exits 1
naming it. The gate set becomes self-verifying — the next fail-open of the
LEDGER-STALE class is caught by `make check-kit`, not by luck.

Fail-closed by construction (LESSONS #6):
  * a mutation whose old-text is missing (the harness was rewritten) or
    ambiguous (matches twice) is a HARD ERROR — the table must track the code,
    exactly like check_lessons_pinned tracks the lessons;
  * a mutated .py that no longer compiles is a HARD ERROR — a SyntaxError would
    fail the self-test for the wrong reason and count as fake coverage;
  * a self-test that dies with a Traceback under mutation is a HARD ERROR for
    the same reason — we are proving verdict coverage, not crash detection;
  * the BASELINE (unmutated copy) must be green first — otherwise red can't be
    attributed to the mutation.

The live tree is never touched: each run works in fresh copies under a temp dir.

Usage:
  mutate_gates.py [KIT_ROOT] [--only GATE[,GATE..]] [--list] [--json]
  mutate_gates.py --self-test
Exit: 0 = every mutation caught; 1 = a survivor (or usage=2).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

# One entry per gate: neutralize the CROWN verdict — the single predicate whose
# silent failure would let the gate pass while checking nothing. `old` must
# appear EXACTLY ONCE in `file` (enforced), so a harness rewrite that moves the
# verdict forces a table update instead of silently mutating dead code.
# (LESSONS #16: this harness's first sweep found a survivor — a bundled
# two-defect fixture that pinned only the union of its checks.)
MUTATIONS = [
    {"gate": "diff_run", "file": "harnesses/differential/diff_run.py",
     "old": "    is_match = stdout_match and exit_match and stderr_match",
     "new": "    is_match = True",
     "why": "every case MATCHes regardless of output/exit",
     "cmd": ["harnesses/differential/diff_run.py", "--self-test"]},

    {"gate": "lib_diff", "file": "harnesses/library-differential/lib_diff.py",
     "old": "    is_match = (not c_bad) and ret_match and out_match",
     "new": "    is_match = True",
     "why": "every vector MATCHes regardless of return/outputs",
     "cmd": ["harnesses/library-differential/lib_diff.py", "--self-test"]},

    {"gate": "cando", "file": "harnesses/cando/cando_diff.py",
     "old": '        oracle_errored = r["oracle_rc"] != 0 or r["timed_out"]["oracle"]',
     "new": "        oracle_errored = False",
     "why": "C-baseline validation gone: a rejected vector still judges Rust",
     "cmd": ["harnesses/cando/cando_diff.py", "--self-test"]},

    {"gate": "diff_fuzz", "file": "harnesses/diff-fuzz/diff_fuzz.py",
     "old": '    return verdict in ("DIVERGE", "TIMEOUT")',
     "new": "    return False",
     "why": "nothing is ever a finding: the fuzzer reports clean on divergence",
     "cmd": ["harnesses/diff-fuzz/diff_fuzz.py", "--self-test"]},

    {"gate": "unsafe-audit", "file": "harnesses/unsafe-audit/audit_unsafe.py",
     "old": "        break  # first real code line: the run is over, not documented\n"
            "    return False",
     "new": "        break  # first real code line: the run is over, not documented\n"
            "    return True",
     "why": "every unsafe block counts as documented",
     "cmd": ["harnesses/unsafe-audit/audit_unsafe.py", "--self-test"]},

    {"gate": "c-flaw-scan", "file": "harnesses/c-flaw-scan/scan_c_flaws.py",
     "old": '    hits.sort(key=lambda h: (h["line"], h["category"]))\n    return hits',
     "new": "    return []",
     "why": "the Phase-0 scanner reports 0 flaws on any C",
     "cmd": ["harnesses/c-flaw-scan/scan_c_flaws.py", "--self-test"]},

    # (LESSONS #21: test expectations are GENERATED from the oracle transcript;
    # a verify that can't see oracle drift would bless any live behavior)
    {"gate": "probe", "file": "harnesses/probe/probe.py",
     "old": '        behavior_matches = rc == e["rc"] and out_b64 == e["stdout_b64"]',
     "new": "        behavior_matches = True",
     "why": "oracle drift invisible: verify blesses any live behavior as pinned",
     "cmd": ["harnesses/probe/probe.py", "--self-test"]},

    {"gate": "golden", "file": "harnesses/golden/golden.py",
     "old": '    matched, note = got == golden, ""',
     "new": '    matched, note = True, ""',
     "why": "replay always MATCHes the golden regardless of output",
     "cmd": ["harnesses/golden/golden.py", "--self-test"]},

    {"gate": "perf", "file": "harnesses/perf/perf_gate.py",
     "old": '            verdict = "OK" if ratio <= threshold else "SLOW"',
     "new": '            verdict = "OK"',
     "why": "no ratio is ever SLOW",
     "cmd": ["harnesses/perf/perf_gate.py", "--self-test"]},

    {"gate": "normalize", "file": "harnesses/differential/normalize.py",
     "old": "    active = list(rules) + ([PID_RULE] if mask_numbers else [])",
     "new": "    active = []",
     "why": "no normalization rule is ever applied",
     "cmd": ["harnesses/differential/normalize.py", "--self-test"]},

    {"gate": "progress", "file": "harnesses/progress/progress.py",
     "old": "    return (isinstance(rep, list) and len(rep) > 0\n"
            '            and all(isinstance(r, dict) and r.get("verdict") in ("MATCH", "DIVERGE(ledgered)")\n'
            "                    for r in rep))",
     "new": "    return True",
     "why": "any differential report (even all-DIVERGE, even empty) advances the gate",
     "cmd": ["harnesses/progress/progress.py", "--self-test"]},

    {"gate": "doc-flags", "file": "harnesses/doc-check/check_doc_flags.py",
     "old": '                if not re.search(r"(?<![\\w-])" + re.escape(flag) + r"(?![\\w-])",\n'
            "                                 sources[script]):",
     "new": "                if False:",
     "why": "every documented flag counts as existing",
     "cmd": ["harnesses/doc-check/check_doc_flags.py", "--self-test"]},

    {"gate": "lessons-pinned", "file": "harnesses/doc-check/check_lessons_pinned.py",
     "old": '    return any("LESSONS" in line and tok.search(line)\n'
            "               for line in file_text.splitlines())",
     "new": "    return True",
     "why": "every amended file counts as citing its lesson",
     "cmd": ["harnesses/doc-check/check_lessons_pinned.py", "--self-test"]},

    {"gate": "threat-model", "file": "harnesses/threat-model/check_threat_model.py",
     "old": "    if problems:",
     "new": "    if False:",
     "why": "placeholders/missing sections never fail the check",
     "cmd": ["harnesses/threat-model/check_threat_model.py", "--self-test"]},

    {"gate": "skills", "file": "skills/check_skills.py",
     "old": "        if not os.path.exists(os.path.join(kit_root, rel)):",
     "new": "        if False:",
     "why": "a skill referencing a deleted kit path is never flagged",
     "cmd": ["skills/check_skills.py", "--self-test"]},
]

_IGNORE = shutil.ignore_patterns(
    ".git", "target", "corpus", "reports", "__pycache__", "fuzz-findings",
    "artifacts", "*.so", "*.o", "*.pyc")


def _copy_kit(kit_root, dst):
    shutil.copytree(kit_root, dst, ignore=_IGNORE, symlinks=True)


def _apply(kit_copy, m):
    """Apply one mutation in the copy. Hard error (fail closed) if the old text
    is missing (stale table) or ambiguous, or if the result doesn't compile."""
    path = os.path.join(kit_copy, m["file"])
    src = open(path, encoding="utf-8").read()
    n = src.count(m["old"])
    if n == 0:
        sys.exit(f"error: mutation table is STALE — {m['gate']}: the target text no "
                 f"longer appears in {m['file']}. The verdict moved; update the "
                 f"table entry (this is the table tracking the code, like "
                 f"check_lessons_pinned tracks the lessons).")
    if n > 1:
        sys.exit(f"error: mutation {m['gate']}: target text appears {n}x in "
                 f"{m['file']} — ambiguous; extend `old` with surrounding context.")
    mutated = src.replace(m["old"], m["new"], 1)
    if path.endswith(".py"):
        try:
            compile(mutated, path, "exec")
        except SyntaxError as e:
            sys.exit(f"error: mutation {m['gate']} breaks the syntax of {m['file']} "
                     f"({e}) — a SyntaxError fails the self-test for the wrong "
                     f"reason and would count as fake coverage. Fix the table.")
    open(path, "w", encoding="utf-8").write(mutated)


def _run(kit_copy, cmd, timeout=300):
    argv = [sys.executable, os.path.join(kit_copy, cmd[0])] + cmd[1:]
    p = subprocess.run(argv, cwd=kit_copy, capture_output=True, text=True,
                       timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def run_gates(kit_root, mutations, as_json=False):
    kit_root = os.path.abspath(kit_root)
    results = []
    with tempfile.TemporaryDirectory(prefix="gate-mutation-") as tmp:
        # Baseline: every self-test must be green UNMUTATED, or red can't be
        # attributed to the mutation.
        clean = os.path.join(tmp, "baseline")
        _copy_kit(kit_root, clean)
        for cmd in {tuple(m["cmd"]) for m in mutations}:
            rc, out = _run(clean, list(cmd))
            if rc != 0:
                sys.exit(f"error: baseline is RED before any mutation — "
                         f"`{' '.join(cmd)}` exits {rc} on a clean copy. Fix that "
                         f"first; mutation results would be meaningless.\n{out[-2000:]}")

        for i, m in enumerate(mutations):
            work = os.path.join(tmp, f"m{i}")
            _copy_kit(kit_root, work)
            _apply(work, m)
            rc, out = _run(work, m["cmd"])
            if rc != 0 and "Traceback (most recent call last)" in out:
                sys.exit(f"error: mutation {m['gate']} CRASHES the self-test "
                         f"(Traceback) instead of failing its checks — that proves "
                         f"crash detection, not verdict coverage. Refine the "
                         f"mutation.\n{out[-2000:]}")
            results.append({"gate": m["gate"], "file": m["file"], "why": m["why"],
                            "caught": rc != 0, "self_test_rc": rc})

    survivors = [r for r in results if not r["caught"]]
    if as_json:
        print(json.dumps({"results": results,
                          "survivors": [r["gate"] for r in survivors]}, indent=2))
    else:
        for r in results:
            print(f"[{'CAUGHT  ' if r['caught'] else 'SURVIVED'}] {r['gate']:16} "
                  f"{r['why']}")
        print(f"\n{len(results)} gate(s) mutated, {len(survivors)} survivor(s)")
        if survivors:
            print("SURVIVED = the gate's verdict was neutralized and its self-test "
                  "STAYED GREEN: that self-test is not pinning the verdict. Add a "
                  "fixture that fails under this mutation.")
    return 1 if survivors else 0


# ---------------------------------------------------------------- self-test --

_TOY_GATE = '''\
#!/usr/bin/env python3
import sys

def is_ok(x):
    # the verdict under test
    return x > 0

def self_test():
    ok = True
    ok &= is_ok(1) is True
    ok &= is_ok(-1) is False    # pins the verdict: red if is_ok is neutralized
    print("self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(self_test())
'''


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    def exits(fn):
        try:
            fn()
            return False
        except SystemExit as e:
            return e.code not in (0, None)

    with tempfile.TemporaryDirectory() as root:
        kit = os.path.join(root, "kit")
        os.makedirs(os.path.join(kit, "harnesses", "toy"))
        gate = os.path.join(kit, "harnesses", "toy", "gate.py")
        open(gate, "w").write(_TOY_GATE)
        base = {"gate": "toy", "file": "harnesses/toy/gate.py",
                "cmd": ["harnesses/toy/gate.py"], "why": "toy verdict"}

        good = dict(base, old="    return x > 0", new="    return True")
        check("a real verdict-neutralization is CAUGHT (suite goes red)",
              run_gates(kit, [good], as_json=False) == 0)

        # a mutation that changes nothing the verdict depends on must SURVIVE,
        # and a survivor must fail the harness — that is the whole point.
        harmless = dict(base, old="    # the verdict under test",
                        new="    # a comment change, verdict intact")
        check("a harmless mutation SURVIVES and the harness exits 1",
              run_gates(kit, [harmless], as_json=False) == 1)

        # stale table: old text absent → hard error, not a silent skip
        stale = dict(base, old="    return x >= 42", new="    return True")
        check("a stale table entry is a hard error (fail closed)",
              exits(lambda: run_gates(kit, [stale])))

        # ambiguous old text → hard error
        open(gate, "a").write("\n# duplicated marker\n#     return x > 0\n")
        ambiguous = dict(base, old="    return x > 0", new="    return True")
        check("an ambiguous match is a hard error",
              exits(lambda: run_gates(kit, [ambiguous])))
        open(gate, "w").write(_TOY_GATE)

        # a mutation that breaks the syntax → hard error (fake coverage guard)
        broken = dict(base, old="    return x > 0", new="    return x >")
        check("a syntax-breaking mutation is a hard error",
              exits(lambda: run_gates(kit, [broken])))

        # a RED baseline → hard error before any mutation runs
        open(gate, "w").write(_TOY_GATE.replace("ok &= is_ok(1) is True",
                                                "ok &= is_ok(1) is False"))
        check("a red baseline is a hard error (red must be attributable)",
              exits(lambda: run_gates(kit, [good])))

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kit_root", nargs="?", help="kit checkout to mutate (a scratch copy is used)")
    ap.add_argument("--only", help="comma-separated gate names to run (default: all)")
    ap.add_argument("--list", action="store_true", help="list the mutation table and exit")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.list:
        for m in MUTATIONS:
            print(f"{m['gate']:16} {m['file']:44} {m['why']}")
        return 0
    if not args.kit_root:
        ap.print_usage(sys.stderr)
        print("error: give KIT_ROOT (usually `.`), or --self-test / --list", file=sys.stderr)
        return 2
    muts = MUTATIONS
    if args.only:
        names = {n.strip() for n in args.only.split(",")}
        unknown = names - {m["gate"] for m in MUTATIONS}
        if unknown:
            sys.exit(f"error: unknown gate(s): {', '.join(sorted(unknown))} "
                     f"(see --list)")
        muts = [m for m in MUTATIONS if m["gate"] in names]
    return run_gates(args.kit_root, muts, as_json=args.json)


if __name__ == "__main__":
    sys.exit(main())
