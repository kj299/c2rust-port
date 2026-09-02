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

Usage:
  check_api.py --header H [--header H2] --manifest API-COVERAGE.md
               [--export-macro CJSON_PUBLIC] [--json]
  check_api.py --self-test
Exit: 0 = every exported symbol accounted for; 1 = one is not; 2 = usage/input error.
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


def check(header_paths, manifest_path, export_macro, as_json=False):
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

    def by_status(want):
        return [s for s in syms
                if s in rows and rows[s][0] == want and (want == "ported" or rows[s][1])]

    ported, scoped, todo = by_status("ported"), by_status("out-of-scope"), by_status("unported")
    declared = declared_max_unported(manifest_path)
    ratchet_ok = ratchet_holds(len(todo), declared)
    failed = bool(missing) or bool(stale) or not ratchet_ok

    if as_json:
        json.dump({"tool": "api-coverage", "symbols": syms, "ported": ported,
                   "out_of_scope": scoped, "unported": todo,
                   "max_unported_declared": declared, "ratchet_ok": ratchet_ok,
                   "unaccounted": missing, "stale_rows": stale,
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
    ap.add_argument("--export-macro", default="CJSON_PUBLIC")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.header or not a.manifest:
        print("error: give --header and --manifest, or --self-test", file=sys.stderr)
        return 2
    return check(a.header, a.manifest, a.export_macro, a.json)


if __name__ == "__main__":
    sys.exit(main())
