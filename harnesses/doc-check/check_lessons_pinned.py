#!/usr/bin/env python3
"""Lessons-pinned check — the smoke tests must track the lessons. Every LESSONS
entry that amends kit CODE (a harness, a workflow, an example runner) must be
cited in that file — and the kit's convention is that the citation sits next to
the self-test check that PINS the lesson, so `make check-kit` is the lessons'
regression suite.

Why (LESSONS #13): a lesson recorded in LESSONS.md is history, not a control —
two logged lessons recurred in code written after them. The one thing that makes
a lesson durable is a pinned check in a harness self-test. This gate makes the
LESSONS↔smoke-test linkage mechanical in both directions:
  * a NEW lesson claiming `Section amended: harnesses/foo.py` fails check-kit
    until foo.py actually cites `LESSONS #N` (added, by convention, at the
    pinned check / the changed logic);
  * a REWRITE of foo.py that drops the lesson's citation (usually by deleting
    the pinned logic) fails check-kit until the lesson is re-pinned.

Mechanics (conservative, format-driven):
  * Parse LESSONS.md entries (`## NNN. <title>`) and each entry's
    `- **Section amended:**` field (the format's required final field).
  * From that field, extract kit CODE paths: `harnesses/`, `skills/`,
    `skeleton/`, `examples/`, `ports/`, or `.github/` files ending in
    .py/.sh/.yml.
    Prose, doc (.md), and bare-basename mentions are not obligations.
  * For each such path that still exists, require a line containing `LESSONS`
    and the token `#<n>` (e.g. `(LESSONS #6)`), any leading zeros ignored.
  * A path that no longer exists is skipped with a note: LESSONS is append-only
    history, and history is allowed to age across renames.

Usage:  check_lessons_pinned.py [KIT_ROOT]   (defaults to this file's ../../)
        check_lessons_pinned.py --self-test
Exit: 0 = every amended code file cites its lesson; 1 = a lesson is unpinned.
"""
from __future__ import annotations

import os
import re
import sys

ENTRY_RE = re.compile(r"(?m)^## (\d{3})\. ")
AMENDED_RE = re.compile(r"- \*\*Section amended:\*\*(.*?)(?=^-\s\*\*|^##\s|\Z)",
                        re.S | re.M)
# `ports/` is in the list because a real port's own gate scripts and corpus
# generators ARE kit code a lesson can amend — the cJSON retrospective found
# LESSONS #19 naming `ports/cjson/oracle/gen_corpus.py` and this gate silently
# ignoring it, because the prefix list predated the existence of `ports/`. A
# path this regex doesn't recognize is checked by nothing and reports nothing:
# the same not-looking-at-it failure as a 0-of-0 audit (LESSONS #18).
CODE_PATH_RE = re.compile(
    r"(?:harnesses|skills|skeleton|examples|ports|\.github)/[A-Za-z0-9_./-]+\.(?:py|sh|yml)")


def parse_lessons(text):
    """Yield (lesson_number, entry_body) for each `## NNN.` entry."""
    marks = [(m.start(), int(m.group(1))) for m in ENTRY_RE.finditer(text)]
    for i, (pos, num) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        yield num, text[pos:end]


def amended_code_paths(entry_body):
    """Code paths named in the entry's `Section amended:` field (deduped).

    A long `Section amended` list is markdown-wrapped, and a wrap can fall
    mid-path right after a `/` (`harnesses/cando/\\n  cando_diff.py`). Left as-is
    the extractor matches neither half and SILENTLY skips that file — a fail-open
    in the very gate that enforces fail-closed pinning (LESSONS #14, a #6
    recurrence). Rejoin any whitespace that immediately follows a `/` before
    extracting, so a wrapped path is checked, not dropped."""
    paths = []
    for m in AMENDED_RE.finditer(entry_body):
        field = re.sub(r"/\s+", "/", m.group(1))
        paths.extend(CODE_PATH_RE.findall(field))
    return list(dict.fromkeys(paths))


def cites(file_text, n):
    """True if some line mentions LESSONS together with the token #<n>."""
    tok = re.compile(rf"#0*{n}\b")
    return any("LESSONS" in line and tok.search(line)
               for line in file_text.splitlines())


def run(kit_root):
    lessons_path = os.path.join(kit_root, "LESSONS.md")
    if not os.path.isfile(lessons_path):
        print(f"error: no LESSONS.md at {kit_root}", file=sys.stderr)
        return 1
    text = open(lessons_path, encoding="utf-8").read()
    problems, checked, aged = [], 0, 0
    for num, body in parse_lessons(text):
        for rel in amended_code_paths(body):
            full = os.path.join(kit_root, rel)
            if not os.path.exists(full):
                aged += 1  # append-only history is allowed to age past renames
                continue
            checked += 1
            if not cites(open(full, encoding="utf-8").read(), num):
                problems.append(
                    f"LESSONS #{num} amends {rel}, but {rel} does not cite "
                    f"`LESSONS #{num}` — re-pin the lesson (cite it at the "
                    f"self-test check / changed logic)")
    for p in problems:
        print("UNPINNED: " + p)
    note = f" ({aged} aged path(s) skipped)" if aged else ""
    print(f"{checked} lesson→code link(s) checked, {len(problems)} unpinned{note}")
    return 1 if problems else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "harnesses", "x"))
        good = os.path.join(root, "harnesses", "x", "good.py")
        open(good, "w").write("# pinned here (LESSONS #7)\ncheck('...')\n")
        open(os.path.join(root, "LESSONS.md"), "w").write(
            "## 007. a lesson\n- **What happened:** ...\n"
            "- **Kit change:** ...\n"
            "- **Section amended:** harnesses/x/good.py (self-test); PLAYBOOK · X.\n")
        check("cited lesson→harness link passes", run(root) == 0)

        # a second lesson amends a file that does NOT cite it → fail
        bad = os.path.join(root, "harnesses", "x", "bad.sh")
        open(bad, "w").write("#!/bin/sh\necho no citation here\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 008. another\n- **Section amended:** harnesses/x/bad.sh.\n")
        check("uncited lesson→harness link is caught", run(root) == 1)

        # citing the WRONG number must not satisfy the link
        open(bad, "w").write("#!/bin/sh\n# (LESSONS #7) wrong entry\n")
        check("citing a different lesson number still fails", run(root) == 1)
        open(bad, "w").write("#!/bin/sh\n# pinned (LESSONS #8)\n")
        check("correct citation clears it", run(root) == 0)

        # a renamed/removed path is aged history, not a failure (append-only)
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 009. old\n- **Section amended:** harnesses/gone/renamed.py.\n")
        check("an amended path that no longer exists is skipped", run(root) == 0)

        # prose/doc mentions outside `Section amended` create no obligation
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 010. prose\n- **What happened:** touched harnesses/x/bad.sh\n"
                    "- **Section amended:** PLAYBOOK · Phase 2 only.\n")
        check("prose mentions outside Section-amended are ignored", run(root) == 0)

        # LESSONS #18/#19: a prefix the extractor doesn't know is checked by
        # NOTHING — `ports/` was missing until a real port's lesson named a file
        # there and the gate silently ignored it.
        os.makedirs(os.path.join(root, "ports", "p"))
        pf = os.path.join(root, "ports", "p", "gate.sh")
        open(pf, "w").write("#!/bin/sh\necho no citation\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 012. ports path\n- **Section amended:** ports/p/gate.sh.\n")
        check("a ports/ path is checked like any other kit code", run(root) == 1)
        open(pf, "w").write("#!/bin/sh\n# pinned (LESSONS #12)\n")
        check("citing it clears the ports/ link", run(root) == 0)

        # LESSONS #14: a path a markdown line-wrap split after a `/` must still be
        # extracted and enforced — else the gate silently skips it (fail-open).
        wrapped = os.path.join(root, "harnesses", "x", "wrapped.py")
        open(wrapped, "w").write("#!/usr/bin/env python3\nprint('no citation')\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 011. wrapped path\n- **Section amended:** harnesses/x/\n"
                    "  wrapped.py (the changed logic).\n")
        check("a line-wrapped amended path is still checked (not skipped)", run(root) == 1)
        open(wrapped, "w").write("#!/usr/bin/env python3\n# pinned (LESSONS #11)\n")
        check("citing it clears the wrapped-path link", run(root) == 0)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    here = os.path.dirname(os.path.abspath(__file__))
    kit_root = argv[0] if argv else os.path.dirname(os.path.dirname(here))
    return run(kit_root)


if __name__ == "__main__":
    sys.exit(main())
