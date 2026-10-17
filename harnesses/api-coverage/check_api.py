#!/usr/bin/env python3
"""API-coverage — every PUBLIC entry point the port claims must be accounted for.

Why (LESSONS #34, mechanizing #26): LESSONS #26 already says "check the driver's
modes against the module's PUBLIC API, not just its pipeline" — and it was written
into `PLAYBOOK` Phase 4 and `PROMPTS/10` step 0 as prose. It then failed to fire on
the very next module: cJSON module 9 shipped "DONE" through six green gates with
**two of `cJSON_Utils.h`'s 14 public symbols never ported and never gated**
(`cJSONUtils_AddPatchToArray`, `cJSONUtils_FindPointerFromObjectTo`). A rule wired
only to a human's reading habit is not wired to anything (the LESSONS #32 shape).
This makes it a check: the port must ACCOUNT for every exported symbol, either
mapping it to the surface that gates it or recording, in writing, why it is out of
scope. Silence is no longer an option.

It also refuses the mistake that produced the first draft of this finding. Reading
the header with a bare identifier grep reported a THIRD missing symbol,
`cJSONUtils_AtomicApplyPatches` — which is a commented-out suggestion inside a
`/* ... */` block with no implementation and no `CJSON_PUBLIC`. So this strips C
comments before matching and requires the export macro, never a bare name: a gate
that invents work is as bad as one that hides it.

The same class of false positive bit again when the checker was pointed at
`cJSON.h`: `#define CJSON_PUBLIC(type) __declspec(dllexport) type CJSON_STDCALL`
*is* a line containing `CJSON_PUBLIC(...)` followed by an identifier and a paren,
so the macro's own DEFINITION was reported as exporting `__declspec` and
`__attribute__`. Preprocessor directive lines are therefore stripped too, with
their backslash continuations. Both false positives are pinned in the self-test:
a checker that manufactures symbols trains you to ignore it.

Mechanics (format-driven, conservative):
  * Symbols = `<EXPORT_MACRO>(<type>) <name>(` in the header, AFTER stripping
    `/* */` and `//` comments and `#...` directive lines. `--export-macro`
    defaults to `CJSON_PUBLIC`; pass your library's (e.g. `ZEXPORT`). With
    `--export-macro ''` it falls back to `extern <type> <name>(` declarations.
  * The manifest is a markdown table: `| symbol | status | note |`, status one of
    `ported` / `out-of-scope` / `unported`. Both non-`ported` statuses MUST carry
    a non-empty note — an unexplained exclusion is the thing this gate exists to
    prevent.
  * A symbol with no row at all fails. A row for an unknown symbol fails too
    (it means the manifest has drifted from the header, e.g. after an upgrade).

THE `unported` RATCHET (LESSONS #35)
  A port mid-flight has entry points that are neither done nor abandoned. Forcing
  that state into `out-of-scope` launders a TODO into a decision — the exact
  laundering this gate exists to stop — and forcing it into `ported` is a lie.
  So `unported` is a real status, and it is governed by a ceiling the manifest
  must state in plain text:

      api-coverage: max-unported = 37

  * more `unported` rows than declared  -> FAIL: the ungated surface GREW.
  * fewer                               -> FAIL: ratchet down, lock the progress in.
  * any `unported` row and no ceiling   -> FAIL.
  Exactly-as-declared passes, and prints the shortfall LOUDLY every run, because
  a green gate over an incomplete API must never read as a complete one.

A `ported` ROW NAMING A MODE NO CASE RUNS (LESSONS #61)
  `ported` means "a driver mode or vector calls it, so the differential compares
  it" — but nothing checked the second half. cJSON's manifest carried five
  `*CaseSensitive` rows reading "driver mode `ptr-cs`" (and four like it) for
  seven weeks after module 9; both drivers implemented those modes and no matrix
  case ran any of them. When they finally ran, the first `patch-cs` input found
  a C defect the port diverged from, unexamined. So, given the port's matrices:

      check_api.py ... --matrix oracle/matrix.json --matrix oracle/matrix-x.json

  every mode a `ported` row names as "driver mode `X`" must be the first argv
  word of at least one case, or the row fails as UNDRIVEN. Matrices are JSON (a
  list, or {"case": [...]}) or TOML ([[case]]); an unreadable one, or matrices
  holding no case at all, cannot be judged (exit 2). Without `--matrix` the
  check is not run — and a row naming a mode is then a claim, not a fact.

Usage:
  check_api.py --header H [--header H2] --manifest API-COVERAGE.md
               [--matrix M [--matrix M2 ...]] [--export-macro CJSON_PUBLIC] [--json]
  check_api.py --self-test
Exit: 0 = every exported symbol accounted for (and, with --matrix, every named
mode driven); 1 = one is not; 2 = usage/input error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")
# A `#...` directive plus any backslash-continued lines. Matched AFTER comments
# are stripped, so `#define X /* c */ y` still collapses to one directive line.
DIRECTIVE = re.compile(r"^[ \t]*#(?:[^\n\\]|\\\n|\\[^\n])*", re.M)
TABLE_ROW = re.compile(r"^\s*\|")
VALID_STATUS = ("ported", "out-of-scope", "unported")
NEEDS_REASON = ("out-of-scope", "unported")
MAX_UNPORTED = re.compile(r"api-coverage:\s*max-unported\s*=\s*(\d+)")
# How a `ported` row names the driver mode that gates it: "driver mode `ptr`".
# Conservative on purpose: in "driver modes `a` and `b`" only `a` is read, so a
# row can under-claim to this check but never be failed for prose it did not
# mean as a mode name. The closing backtick may be gone: manifest_rows strips
# backticks from both ENDS of a cell, so a note ending in "driver mode `ptr`"
# arrives as "driver mode `ptr" — and a pattern requiring the closer matched
# nothing there and passed every row, which the self-test's first fixture
# (written the way the real manifest is) caught.
DRIVER_MODE = re.compile(r"\bdriver modes?\s+`([^`]+)(?:`|$)")


def strip_comments(text):
    """Remove C comments so a commented-out declaration is never a symbol."""
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub("", text))


def strip_directives(text):
    """Remove preprocessor lines so the EXPORT MACRO'S OWN `#define` is not read
    as a declaration. In cJSON.h that definition is spelled
    `#define CJSON_PUBLIC(type) __declspec(dllexport) type CJSON_STDCALL`,
    which the declaration pattern happily reads as exporting `__declspec`."""
    return DIRECTIVE.sub("", text)


def exported_symbols(header_paths, export_macro):
    syms = []
    for p in header_paths:
        with open(p, encoding="utf-8") as fh:
            src = strip_directives(strip_comments(fh.read()))
        if export_macro:
            pat = re.compile(re.escape(export_macro) + r"\s*\([^)]*\)\s*\*?\s*([A-Za-z_]\w*)\s*\(")
        else:
            pat = re.compile(r"^\s*extern\s+[^;()]+?\*?\s*([A-Za-z_]\w*)\s*\(", re.M)
        for m in pat.finditer(src):
            if m.group(1) not in syms:
                syms.append(m.group(1))
    return syms


def manifest_rows(manifest_path):
    """{symbol: (status, note)} from the manifest's markdown table."""
    rows = {}
    with open(manifest_path, encoding="utf-8") as fh:
        for line in fh:
            if not TABLE_ROW.match(line):
                continue
            cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
            if len(cells) < 2:
                continue
            sym, status = cells[0], cells[1].lower()
            if status not in VALID_STATUS:      # header/separator rows fall out here
                continue
            rows[sym] = (status, cells[2].strip() if len(cells) > 2 else "")
    return rows


def declared_max_unported(manifest_path):
    """The ceiling the manifest states in plain text, or None if it states none."""
    with open(manifest_path, encoding="utf-8") as fh:
        m = MAX_UNPORTED.search(fh.read())
    return int(m.group(1)) if m else None


def symbol_is_accounted(sym, rows):
    """THE VERDICT (one predicate, so gate-mutation can neutralize it and the
    self-test's negative fixtures must then go red — LESSONS #25)."""
    if sym not in rows:
        return False
    status, note = rows[sym]
    if status in NEEDS_REASON and not note:
        return False                            # an unexplained exclusion is not an account
    return True


def ratchet_holds(actual, declared):
    """THE SECOND VERDICT — the `unported` ceiling. Separate predicate on purpose:
    the mutation sweep neutralizes each verdict independently, and this one governs
    a different failure (a growing ungated surface) than `symbol_is_accounted`
    (an unexplained one). `declared is None` with any unported row is a failure,
    not a default: an unstated ceiling is an infinite one."""
    if actual == 0:
        return declared in (None, 0)
    if declared is None:
        return False
    return actual == declared


def named_modes(rows):
    """{mode: [symbols]} for every driver mode a `ported` row names."""
    named = {}
    for sym, (status, note) in rows.items():
        if status != "ported":
            continue
        for m in DRIVER_MODE.finditer(note):
            named.setdefault(m.group(1), []).append(sym)
    return named


def matrix_modes(paths):
    """The set of first argv words across every case in the matrices; None,
    reported, when a matrix is unreadable or the matrices hold no case at all
    (a mode check over zero cases proves nothing — LESSONS #18)."""
    modes, cases_seen = set(), 0
    for p in paths:
        try:
            if p.endswith(".toml"):
                import tomllib
                with open(p, "rb") as fh:
                    data = tomllib.load(fh)
            else:
                with open(p, encoding="utf-8") as fh:
                    data = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"error: cannot read matrix {p}: {e}", file=sys.stderr)
            return None
        cases = data.get("case", []) if isinstance(data, dict) else data
        if not isinstance(cases, list):
            print(f"error: matrix {p}: cases are not a list", file=sys.stderr)
            return None
        for case in cases:
            args = case.get("args") if isinstance(case, dict) else None
            if isinstance(args, list) and args:
                modes.add(str(args[0]))
            cases_seen += 1
    if cases_seen == 0:
        print(f"error: no cases in {', '.join(paths)} — a mode check over zero "
              "cases proves nothing", file=sys.stderr)
        return None
    return modes


def mode_is_driven(mode, driven):
    """THE THIRD VERDICT (LESSONS #61): a mode a `ported` row names is run by
    at least one matrix case. Its own predicate, like the other two, so the
    gate-mutation sweep can neutralize it alone."""
    return mode in driven


def check(header_paths, manifest_path, export_macro, as_json=False, matrices=None):
    for p in list(header_paths) + [manifest_path]:
        if not os.path.isfile(p):
            print(f"error: not found: {p}", file=sys.stderr)
            return 2

    syms = exported_symbols(header_paths, export_macro)
    if not syms:
        # 0-of-0 proves nothing and must not pass (LESSONS #18).
        print(f"error: no exported symbols found in {', '.join(header_paths)} "
              f"(export macro {export_macro!r}) — a coverage check over zero "
              "symbols proves nothing", file=sys.stderr)
        return 2

    rows = manifest_rows(manifest_path)
    missing = [s for s in syms if not symbol_is_accounted(s, rows)]
    stale = [s for s in rows if s not in syms]
    undriven = {}
    if matrices:
        driven = matrix_modes(matrices)
        if driven is None:
            return 2
        undriven = {m: syms_ for m, syms_ in sorted(named_modes(rows).items())
                    if not mode_is_driven(m, driven)}

    def by_status(want):
        return [s for s in syms
                if s in rows and rows[s][0] == want and (want == "ported" or rows[s][1])]

    ported, scoped, todo = by_status("ported"), by_status("out-of-scope"), by_status("unported")
    declared = declared_max_unported(manifest_path)
    ratchet_ok = ratchet_holds(len(todo), declared)
    failed = bool(missing) or bool(stale) or not ratchet_ok or bool(undriven)

    if as_json:
        json.dump({"tool": "api-coverage", "symbols": syms, "ported": ported,
                   "out_of_scope": scoped, "unported": todo,
                   "max_unported_declared": declared, "ratchet_ok": ratchet_ok,
                   "unaccounted": missing, "stale_rows": stale,
                   "undriven_modes": undriven,
                   "ok": not failed}, sys.stdout, indent=1)
        print()
    else:
        for s in syms:
            if s in missing:
                print(f"  UNACCOUNTED  {s}", file=sys.stderr)
            else:
                # `.get`, not `rows[s]`: the verdict predicate is the only thing
                # that decides accountedness, so reporting must not assume a row
                # exists. (The gate-mutation sweep found this: neutralizing the
                # verdict made this line raise KeyError, and a Traceback is a
                # hard error there — we prove verdict coverage, not crashes.)
                print(f"  {rows.get(s, ('?', ''))[0]:<12} {s}")
        for s in stale:
            print(f"  STALE ROW    {s} (in manifest, not exported by the header)",
                  file=sys.stderr)
        if missing or stale:
            print(f"\napi-coverage FAILED: {len(missing)} unaccounted, {len(stale)} stale.\n"
                  "Every exported symbol needs a manifest row:\n"
                  "  | <symbol> | ported | <the driver mode / fn that gates it> |\n"
                  "  | <symbol> | unported | <not done yet — what is missing> |\n"
                  "  | <symbol> | out-of-scope | <why it will never be ported> |\n"
                  "An entry point no mode reaches is ungated whatever the matrix says "
                  "(LESSONS #26).", file=sys.stderr)
        if undriven:
            for m, by in undriven.items():
                print(f"  UNDRIVEN     driver mode `{m}` (named by {', '.join(by)})"
                      " — no matrix case runs it", file=sys.stderr)
            print(f"\napi-coverage FAILED: {len(undriven)} driver mode(s) a `ported` "
                  "row names are run by no case, so the differential compares "
                  "nothing there. Add cases for the mode, or say in the row what "
                  "does gate the symbol (LESSONS #61).", file=sys.stderr)
        if not ratchet_ok:
            print(f"\napi-coverage FAILED the unported ratchet: {len(todo)} unported, "
                  f"manifest declares {declared}.", file=sys.stderr)
            if declared is None:
                print("  State the ceiling in the manifest, in plain text:\n"
                      f"      api-coverage: max-unported = {len(todo)}\n"
                      "  An unstated ceiling is an infinite one.", file=sys.stderr)
            elif len(todo) > declared:
                print("  The UNGATED surface GREW. Port the new entry points, or "
                      "raise the ceiling deliberately and say why.", file=sys.stderr)
            else:
                print(f"  Progress to lock in: ratchet the ceiling down to {len(todo)}.",
                      file=sys.stderr)
        if not failed:
            line = (f"\napi coverage: {len(syms)} exported symbol(s) — "
                    f"{len(ported)} ported, {len(scoped)} out-of-scope with a reason")
            if matrices:
                line += (f"; every driver mode a ported row names "
                         f"({len(named_modes(rows))}) is run by a case")
            if todo:
                # Loud on every run: green here means "exactly as incomplete as
                # declared", never "complete". A ceiling you stop seeing is a
                # ceiling you stop lowering.
                line += (f", {len(todo)} UNPORTED (ceiling {declared})\n"
                         f"api coverage: this port does NOT cover its C library's "
                         f"public API — {len(todo)} of {len(syms)} entry points are "
                         f"ungated. See the manifest's unported rows.")
            print(line)
    return 1 if failed else 0


def _self_test():
    import tempfile
    ok = True

    def case(label, cond):
        nonlocal ok
        print(f"{'PASS' if cond else 'FAIL'}  {label}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        hdr = os.path.join(d, "lib.h")
        with open(hdr, "w", encoding="utf-8") as fh:
            fh.write(
                # cJSON.h's real shape: the export macro defines ITSELF, several
                # times, under #ifdef — each definition a line that looks like a
                # declaration to the pattern below.
                "#ifdef LIB_EXPORT_SYMBOLS\n"
                "#define CJSON_PUBLIC(type)   __declspec(dllexport) type LIB_STDCALL\n"
                "#else\n"
                "#define CJSON_PUBLIC(type)   __attribute__((visibility(\"default\"))) type\n"
                "#endif\n"
                "#define LIB_WRAP(x) \\\n"
                "    CJSON_PUBLIC(int) lib_Continued(x)\n"
                "CJSON_PUBLIC(char *) lib_GetPointer(const cJSON *o);\n"
                "CJSON_PUBLIC(void) lib_AddPatch(cJSON *a, const char *op);\n"
                "/*\n"
                "// Note: not implemented. To do it yourself use:\n"
                "//int lib_AtomicApply(cJSON **o, cJSON *p)\n"
                "*/\n"
                "// CJSON_PUBLIC(int) lib_Commented(void);\n")

        syms = exported_symbols([hdr], "CJSON_PUBLIC")
        case("exported symbols found", syms == ["lib_GetPointer", "lib_AddPatch"])
        # THE regression for the false positive this gate was born from:
        case("a commented-out declaration is NOT a symbol",
             "lib_AtomicApply" not in syms and "lib_Commented" not in syms)
        # ...and for its sibling, found when the gate was pointed at cJSON.h:
        case("the export macro's own #define is NOT a symbol",
             "__declspec" not in syms and "__attribute__" not in syms)
        case("a backslash-continued directive is fully stripped",
             "lib_Continued" not in syms)

        good = os.path.join(d, "good.md")
        with open(good, "w", encoding="utf-8") as fh:
            fh.write("| Symbol | Status | Where |\n|---|---|---|\n"
                     "| `lib_GetPointer` | ported | driver mode `ptr` |\n"
                     "| `lib_AddPatch` | out-of-scope | pure constructor, no observable contract |\n")
        case("a fully accounted manifest passes", check([hdr], good, "CJSON_PUBLIC") == 0)

        # NEGATIVE FIXTURE: the exact failure this gate exists to catch.
        partial = os.path.join(d, "partial.md")
        with open(partial, "w", encoding="utf-8") as fh:
            fh.write("| Symbol | Status | Where |\n|---|---|---|\n"
                     "| `lib_GetPointer` | ported | driver mode `ptr` |\n")
        case("an unported, unlisted symbol FAILS", check([hdr], partial, "CJSON_PUBLIC") == 1)
        case("verdict predicate refuses an unlisted symbol",
             symbol_is_accounted("lib_AddPatch", {}) is False)

        # an out-of-scope row with no reason is not an account
        noreason = os.path.join(d, "noreason.md")
        with open(noreason, "w", encoding="utf-8") as fh:
            fh.write("| Symbol | Status | Where |\n|---|---|---|\n"
                     "| `lib_GetPointer` | ported | mode |\n"
                     "| `lib_AddPatch` | out-of-scope |  |\n")
        case("out-of-scope with NO written reason fails",
             check([hdr], noreason, "CJSON_PUBLIC") == 1)

        # manifest drift: a row for a symbol the header no longer exports
        drifted = os.path.join(d, "drift.md")
        with open(drifted, "w", encoding="utf-8") as fh:
            fh.write("| Symbol | Status | Where |\n|---|---|---|\n"
                     "| `lib_GetPointer` | ported | mode |\n"
                     "| `lib_AddPatch` | ported | mode |\n"
                     "| `lib_Removed` | ported | mode |\n")
        case("a stale manifest row fails", check([hdr], drifted, "CJSON_PUBLIC") == 1)

        # ---- the `unported` ratchet (LESSONS #35) ------------------------
        def manifest(name, addpatch_row, extra=""):
            p = os.path.join(d, name)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("| Symbol | Status | Where |\n|---|---|---|\n"
                         "| `lib_GetPointer` | ported | driver mode `ptr` |\n"
                         f"{addpatch_row}{extra}")
            return p

        UNPORTED = "| `lib_AddPatch` | unported | no driver mode reaches it yet |\n"
        case("unported + a matching ceiling passes",
             check([hdr], manifest("r_ok.md", UNPORTED,
                                   "\napi-coverage: max-unported = 1\n"),
                   "CJSON_PUBLIC") == 0)
        case("unported with NO ceiling fails (an unstated ceiling is infinite)",
             check([hdr], manifest("r_none.md", UNPORTED), "CJSON_PUBLIC") == 1)
        case("the ungated surface GROWING past the ceiling fails",
             check([hdr], manifest("r_grew.md", UNPORTED,
                                   "\napi-coverage: max-unported = 0\n"),
                   "CJSON_PUBLIC") == 1)
        case("a ceiling left above reality fails (ratchet down)",
             check([hdr], manifest("r_slack.md", UNPORTED,
                                   "\napi-coverage: max-unported = 5\n"),
                   "CJSON_PUBLIC") == 1)
        case("unported with NO written reason fails",
             check([hdr], manifest("r_mute.md", "| `lib_AddPatch` | unported |  |\n",
                                   "\napi-coverage: max-unported = 1\n"),
                   "CJSON_PUBLIC") == 1)
        case("ratchet predicate: unstated ceiling is not a pass",
             ratchet_holds(3, None) is False)
        case("ratchet predicate: slack is not a pass", ratchet_holds(1, 5) is False)
        case("ratchet predicate: exact match passes", ratchet_holds(3, 3) is True)
        # With NOTHING unported, a ceiling above zero is slack all the same: room
        # for three ungated symbols to arrive unseen. Slack was pinned only for a
        # non-zero count; LESSONS #48's decision sweep found that forcing the
        # zero branch's `declared in (None, 0)` True left this self-test green.
        PORTED = "| `lib_AddPatch` | ported | driver mode `patch` |\n"
        case("nothing unported under a ceiling of 0 passes",
             check([hdr], manifest("r_zero.md", PORTED,
                                   "\napi-coverage: max-unported = 0\n"),
                   "CJSON_PUBLIC") == 0)
        case("nothing unported under a ceiling of 3 fails (ratchet down to 0)",
             check([hdr], manifest("r_zero_slack.md", PORTED,
                                   "\napi-coverage: max-unported = 3\n"),
                   "CJSON_PUBLIC") == 1)
        case("ratchet predicate: slack over an empty surface is not a pass",
             ratchet_holds(0, 3) is False)

        # ---- a `ported` row naming a mode no case runs (LESSONS #61) -------
        modes_md = manifest("m.md",
                            "| `lib_AddPatch` | ported | same, driver mode `ptr-cs` |\n"
                            "| `lib_Gone` | out-of-scope | was driver mode `zzz` |\n")
        # lib_Gone is not exported: drop it so only the mode check can fail
        with open(modes_md, encoding="utf-8") as fh:
            body = fh.read().replace("| `lib_Gone` | out-of-scope | was driver mode `zzz` |\n", "")
        with open(modes_md, "w", encoding="utf-8") as fh:
            fh.write(body + "\napi-coverage: max-unported = 0\n")

        def matrix(name, modes, toml=False):
            p = os.path.join(d, name)
            with open(p, "w", encoding="utf-8") as fh:
                if toml:
                    fh.write("".join(f'[[case]]\nname = "{m}"\nargs = ["{m}"]\n'
                                     for m in modes))
                else:
                    json.dump([{"name": m, "args": [m], "stdin": ""} for m in modes], fh)
            return p

        only_ptr = matrix("only_ptr.json", ["ptr"])
        both = matrix("both.json", ["ptr", "ptr-cs"])
        case("a ported row naming a mode no case runs FAILS (the ptr-cs gap)",
             check([hdr], modes_md, "CJSON_PUBLIC", matrices=[only_ptr]) == 1)
        case("...and passes once a case runs the mode",
             check([hdr], modes_md, "CJSON_PUBLIC", matrices=[both]) == 0)
        case("cases split across matrices count together",
             check([hdr], modes_md, "CJSON_PUBLIC",
                   matrices=[only_ptr, matrix("cs.toml", ["ptr-cs"], toml=True)]) == 0)
        case("without --matrix the mode check does not run",
             check([hdr], modes_md, "CJSON_PUBLIC") == 0)
        case("an unreadable matrix cannot be judged",
             check([hdr], modes_md, "CJSON_PUBLIC",
                   matrices=[os.path.join(d, "nope.json")]) == 2)
        case("matrices with no case cannot be judged (0-of-0)",
             check([hdr], modes_md, "CJSON_PUBLIC", matrices=[matrix("none.json", [])]) == 2)
        case("a mode named at the END of a cell (its closing ` stripped) is read",
             named_modes(manifest_rows(modes_md)) == {"ptr": ["lib_GetPointer"],
                                                      "ptr-cs": ["lib_AddPatch"]})
        case("only `ported` rows are held to the modes they name",
             named_modes({"a": ("out-of-scope", "driver mode `x`"),
                          "b": ("ported", "driver mode `y`")}) == {"y": ["b"]})
        case("mode predicate: an undriven mode is not driven",
             mode_is_driven("ptr-cs", {"ptr"}) is False)
        case("mode predicate: a driven mode is", mode_is_driven("ptr", {"ptr"}) is True)

        # 0-of-0 must not pass
        empty = os.path.join(d, "empty.h")
        with open(empty, "w", encoding="utf-8") as fh:
            fh.write("/* nothing exported */\n")
        case("a header exporting nothing fails (0-of-0)",
             check([empty], good, "CJSON_PUBLIC") == 2)
        case("a missing file fails closed",
             check([os.path.join(d, "nope.h")], good, "CJSON_PUBLIC") == 2)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--manifest")
    ap.add_argument("--matrix", action="append", default=[],
                    help="a differential matrix (repeat per file): every driver mode "
                         "a `ported` row names must be run by one of its cases")
    ap.add_argument("--export-macro", default="CJSON_PUBLIC")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.header or not a.manifest:
        print("error: give --header and --manifest, or --self-test", file=sys.stderr)
        return 2
    return check(a.header, a.manifest, a.export_macro, a.json, a.matrix)


if __name__ == "__main__":
    sys.exit(main())
