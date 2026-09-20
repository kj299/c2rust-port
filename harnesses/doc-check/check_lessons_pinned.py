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

Two things this gate reports are the two places it can hide, and both were
found by running the harness in a kit that had VENDORED it (LESSONS #044):

  * **The field name is a key.** `AMENDED_RE` matched `- **Section amended:**`
    and nothing else, so `- **Section amended (source lineage):**` — or any
    other parenthesised variant — was not an unrecognised field, it was *no
    field at all*. The entry's obligations vanished and the run printed
    `0 lesson→code link(s) checked`, the kit's own 0-of-0 signature
    (LESSONS #018), as a pass. Anyone could silence this gate by adding a word.
    Now: the bare field carries the obligation, `(source lineage)` is a
    DESIGNED exemption allowed only on an entry carrying `- **Imported:**`
    (its paths counted and printed), and **any other variant is a failure**,
    because a field spelling this file does not know is a claim nobody reads.
  * **A skip counter is where a gate hides.** `aged path(s) skipped` reads like
    benign history and is the right answer for a renamed file. It was also the
    answer given for six live `.github/workflows/*.yml` files in a vendored
    copy of this kit, which sits at `porting-kit/` inside its host repo — so
    the workflows lessons amend most often are one directory UP from KIT_ROOT.
    Four of those six were genuinely unpinned. `--also-scan DIR` reaches them,
    and `aged` vs `resolved outside the kit` are separate numbers so they can
    never merge back into one.

Usage:  check_lessons_pinned.py [KIT_ROOT] [--also-scan DIR]...
            KIT_ROOT defaults to this file's ../../. --also-scan may repeat; a
            path is tried against KIT_ROOT first, then each extra root in turn.
            A --also-scan naming a missing directory is a hard failure, not a
            silent empty scan.
        check_lessons_pinned.py --self-test
Exit: 0 = every amended code file cites its lesson; 1 = a lesson is unpinned.
"""
from __future__ import annotations

import os
import re
import sys

ENTRY_RE = re.compile(r"(?m)^## (\d{3})\. ")

# Every `Section amended` field, whatever parenthesised variant it carries. The
# variant is CAPTURED rather than required to be empty, because a field spelling
# this file does not recognise must be reported, not skipped: matching the bare
# form exactly is what let `(source lineage)` — and `(anything at all)` — drop an
# entry's obligations while the run line said `0 lesson→code link(s) checked`.
#
# A field is a POSITION, not a string. It must OPEN its line, after nothing but
# whitespace — and it is read from the entry with fenced code blocks removed.
# Both rules are here because this harness's own LESSONS entry quotes the field
# it describes, inline and in a worked example, and the first draft of that
# entry was flagged twice by the check it was documenting. Any in-band marker a
# document has to be able to DISCUSS needs a rule separating use from mention,
# or writing the documentation breaks the tool.
AMENDED_ANY_RE = re.compile(
    r"^[ \t]*- \*\*Section amended(?P<variant>[^:*\n]*)\:\*\*(?P<field>.*?)"
    r"(?=^[ \t]*-\s\*\*|^##\s|\Z)", re.S | re.M)
FENCE_RE = re.compile(r"^[ \t]*```.*?^[ \t]*```[ \t]*$", re.S | re.M)
# The one recognised variant, and the only one that lifts the obligation. An
# IMPORTED entry's amendments happened in the lineage it came from: its field
# names that kit's files, several of which do not exist here, so attributing
# them locally would be a false claim. Allowed ONLY on an entry that carries
# `- **Imported:**` — a native lesson may not attribute its own work elsewhere.
ELSEWHERE_VARIANT = " (source lineage)"
IMPORTED_RE = re.compile(r"^\s*-\s+\*\*Imported:\*\*", re.M)
# `ports/` is in the list because a real port's own gate scripts and corpus
# generators ARE kit code a lesson can amend — the cJSON retrospective found
# LESSONS #19 naming `ports/cjson/oracle/gen_corpus.py` and this gate silently
# ignoring it, because the prefix list predated the existence of `ports/`. A
# path this regex doesn't recognize is checked by nothing and reports nothing:
# the same not-looking-at-it failure as a 0-of-0 audit (LESSONS #18).
# `.rs`/`.c`/`.h` joined the extension list with LESSONS #26: a lesson can amend
# a port's Rust or its C driver directly (module 8's fix lives in dom.rs), and
# until then those links were silently unenforced — the extension-list twin of
# the prefix-list gap above.
CODE_PATH_RE = re.compile(
    r"(?:harnesses|skills|skeleton|examples|ports|\.github)/[A-Za-z0-9_./-]+"
    r"\.(?:py|sh|yml|rs|c|h)\b")


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
    for variant, field in amended_fields(entry_body):
        if variant:
            continue  # a variant field is classified by `run`
        paths.extend(_paths_in(field))
    return list(dict.fromkeys(paths))


def _paths_in(field):
    """Code paths in one `Section amended` field, with wrapped paths rejoined."""
    return CODE_PATH_RE.findall(re.sub(r"/\s+", "/", field))


def amended_fields(entry_body):
    """Yield (variant, field_text) for every `Section amended` field, variant
    normalised to `` for the bare form and e.g. ` (source lineage)` otherwise.

    Fenced code blocks are removed first: an entry may show the field inside a
    worked example without thereby declaring one."""
    for m in AMENDED_ANY_RE.finditer(FENCE_RE.sub("", entry_body)):
        v = m.group("variant")
        yield (v if v.strip() else ""), m.group("field")


def resolve(roots, rel):
    """(full path, root it was found under) for `rel`, or (None, None).

    Tried against each root in order, KIT_ROOT first — so a host-repo file a
    vendored kit's lesson amends (`.github/workflows/…`) resolves instead of
    being written off as aged, while a kit file still wins over a same-named
    host file."""
    for r in roots:
        full = os.path.join(r, rel)
        if os.path.exists(full):
            return full, r
    return None, None


def cites(file_text, n):
    """True if some line mentions LESSONS together with the token #<n>."""
    tok = re.compile(rf"#0*{n}\b")
    return any("LESSONS" in line and tok.search(line)
               for line in file_text.splitlines())


def run(kit_root, also=()):
    lessons_path = os.path.join(kit_root, "LESSONS.md")
    if not os.path.isfile(lessons_path):
        print(f"error: no LESSONS.md at {kit_root}", file=sys.stderr)
        return 1
    # A mistyped --also-scan must not look like a clean run: it would silently
    # restore the fail-open the flag exists to close (LESSONS #013's own rule).
    for d in also:
        if not os.path.isdir(d):
            print(f"FAIL  --also-scan {d}: no such directory")
            return 1
    roots = [kit_root, *also]
    text = open(lessons_path, encoding="utf-8").read()
    problems, checked, aged, elsewhere, outside = [], 0, 0, 0, 0
    for num, body in parse_lessons(text):
        for variant, field in amended_fields(body):
            if not variant:
                continue
            if variant != ELSEWHERE_VARIANT:
                problems.append(
                    f"LESSONS #{num} writes `Section amended{variant}:` — this "
                    f"gate knows only the bare field and `{ELSEWHERE_VARIANT}`, "
                    f"so an unrecognised spelling drops the entry's obligations "
                    f"silently. Use one of the two, or teach this harness the "
                    f"new one")
            elif not IMPORTED_RE.search(body):
                problems.append(
                    f"LESSONS #{num} uses `Section amended{ELSEWHERE_VARIANT}` "
                    f"but is not an imported entry — a native lesson's "
                    f"amendments happened HERE, and attributing them elsewhere "
                    f"silences this gate")
            else:
                elsewhere += len(_paths_in(field))
        for rel in amended_code_paths(body):
            full, found_in = resolve(roots, rel)
            if full is None:
                aged += 1  # append-only history is allowed to age past renames
                continue
            if found_in != kit_root:
                outside += 1
            checked += 1
            if not cites(open(full, encoding="utf-8").read(), num):
                problems.append(
                    f"LESSONS #{num} amends {rel}, but {rel} does not cite "
                    f"`LESSONS #{num}` — re-pin the lesson (cite it at the "
                    f"self-test check / changed logic)")
    for p in problems:
        print("UNPINNED: " + p)
    note = f" ({aged} aged path(s) skipped)" if aged else ""
    if outside:
        note += f", {outside} resolved outside the kit"
    if elsewhere:
        note += f", {elsewhere} attributed to the source lineage"
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

        # LESSONS #26: a lesson can amend a port's RUST or C source directly —
        # an extension the regex doesn't know is the extension-list twin of the
        # ports/ prefix gap: named, checked by nothing, reported as nothing.
        rs = os.path.join(root, "ports", "p", "dom.rs")
        open(rs, "w").write("// no citation yet\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 013. rust path\n- **Section amended:** ports/p/dom.rs.\n")
        check("a .rs amended path is checked like any other kit code",
              run(root) == 1)
        open(rs, "w").write("// pinned (LESSONS #13)\n")
        check("citing it clears the .rs link", run(root) == 0)
        cfile = os.path.join(root, "ports", "p", "driver.c")
        open(cfile, "w").write("/* no citation */\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write("\n## 014. c path\n- **Section amended:** ports/p/driver.c.\n")
        check("a .c amended path is checked too", run(root) == 1)
        open(cfile, "w").write("/* pinned (LESSONS #14) */\n")
        check("citing it clears the .c link", run(root) == 0)

        # LESSONS #044, half one. The field NAME is a key. Matching the bare
        # spelling exactly meant a parenthesised one was not an unknown field
        # but no field, so the entry's obligations vanished and the run line
        # said "0 links checked" — a 0-of-0 pass (LESSONS #018) reachable by
        # typing a word. Fixture numbers are assembled, not written: this file
        # is scanned for citations, and a literal one here is a claim wherever
        # it lands.
        F15, F16 = "0" + "1" + "5", "0" + "1" + "6"
        stray = os.path.join(root, "harnesses", "x", "stray.py")
        open(stray, "w").write("# no citation\n")
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write(f"\n## {F15}. variant field\n"
                    "- **Section amended (whatever I like):** "
                    "harnesses/x/stray.py.\n")
        check("an UNRECOGNISED `Section amended (...)` variant is a failure, "
              "not a silent exemption", run(root) == 1)
        # the one recognised variant, on a NATIVE entry, is still a failure
        s = open(os.path.join(root, "LESSONS.md")).read().replace(
            "(whatever I like)", "(source lineage)")
        open(os.path.join(root, "LESSONS.md"), "w").write(s)
        check("`(source lineage)` on a non-imported entry is still a failure",
              run(root) == 1)
        # ...and is allowed, and COUNTED, once the entry declares the import
        s = s.replace("- **Section amended (source lineage):**",
                      "- **Imported:** from a sibling lineage.\n"
                      "- **Section amended (source lineage):**")
        open(os.path.join(root, "LESSONS.md"), "w").write(s)
        check("`(source lineage)` on an IMPORTED entry is the designed exemption",
              run(root) == 0)
        # The variant verdict ISOLATED from the imported-entry verdict. Without
        # this case the two are only pinned together: an entry that is imported
        # AND uses an unknown spelling is where a "known variants only" check
        # can be neutralized with every other fixture staying green — which is
        # exactly what the gate-mutation sweep reported on the first draft here.
        s2 = s.replace("(source lineage)", "(source lineage, mostly)")
        open(os.path.join(root, "LESSONS.md"), "w").write(s2)
        check("an unknown variant fails even on an IMPORTED entry",
              run(root) == 1)
        open(os.path.join(root, "LESSONS.md"), "w").write(s)

        # A field is a POSITION: an entry that DISCUSSES the field — inline in
        # prose, or in a fenced worked example — declares nothing. Both cases
        # are real: #044's own entry does each once, and the first draft of it
        # was flagged twice by the check it documents.
        F17 = "0" + "1" + "7"
        with open(os.path.join(root, "LESSONS.md"), "a") as f:
            f.write(f"\n## {F17}. an entry that quotes the field\n"
                    "- **What happened:** a copy wrote\n"
                    "  `- **Section amended (source lineage):**` and it passed.\n"
                    "  Worked example:\n\n"
                    "```\n"
                    "- **Section amended:** harnesses/x/bad.sh\n"
                    "- **Section amended (whatever):** harnesses/x/bad.sh\n"
                    "```\n\n"
                    "- **Section amended:** PLAYBOOK · one line.\n")
        check("a field quoted inline or fenced is a MENTION, not a declaration",
              run(root) == 0)

        # LESSONS #044, half two: a vendored kit's lessons amend host-repo
        # files one directory up. Pinned in BOTH directions — without the flag
        # the host file is silently skipped, which is the fail-open itself, so
        # dropping `--also-scan` from a Makefile is a behaviour change rather
        # than silence.
        with tempfile.TemporaryDirectory() as hostdir:
            os.makedirs(os.path.join(hostdir, ".github", "workflows"))
            wf = os.path.join(hostdir, ".github", "workflows", "ci.yml")
            open(wf, "w").write("name: ci\njobs: {}\n")
            with open(os.path.join(root, "LESSONS.md"), "a") as f:
                f.write(f"\n## {F16}. host workflow\n"
                        "- **Section amended:** .github/workflows/ci.yml.\n")
            check("a host-repo path is SKIPPED without --also-scan (the fail-open)",
                  run(root) == 0)
            check("--also-scan reaches it, and an uncited host file fails",
                  run(root, [hostdir]) == 1)
            open(wf, "w").write(f"name: ci\n# pinned (LESSONS #{F16})\njobs: {{}}\n")
            check("citing it in the host file clears the link",
                  run(root, [hostdir]) == 0)
            check("a mistyped --also-scan fails rather than scanning nothing",
                  run(root, [os.path.join(hostdir, "no-such-dir")]) == 1)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    here = os.path.dirname(os.path.abspath(__file__))
    kit_root, also, i = None, [], 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--also-scan":
            i += 1
            if i >= len(argv):
                print("FAIL  --also-scan needs a directory")
                return 1
            also.append(argv[i])
        elif arg.startswith("--also-scan="):
            also.append(arg.split("=", 1)[1])
        elif arg.startswith("-"):
            print(f"FAIL  unknown option {arg}")
            return 1
        elif kit_root is None:
            kit_root = arg
        else:
            print(f"FAIL  unexpected argument {arg} (one KIT_ROOT only; "
                  f"use --also-scan for extra roots)")
            return 1
        i += 1
    if kit_root is None:
        kit_root = os.path.dirname(os.path.dirname(here))
    return run(kit_root, also)


if __name__ == "__main__":
    sys.exit(main())
