#!/usr/bin/env python3
"""C vulnerability-class scanner — run at Phase 0, BEFORE porting, so the Rust
rewrite fixes C's latent flaws instead of faithfully re-implementing them.
("Recognize that the existing operating system running code may have other
flaws." — the prime directive.)

This is a fast, dependency-free heuristic grep over C sources for the classic
sink patterns. It is deliberately noisy: every hit is a *question* for the porter
("is this exploitable? does the Rust version close it?"), and confirmed ones go
into DIVERGENCES.md as intentional fix-of-C-defect entries. It does NOT replace a
real SAST pass (clang analyzer, CodeQL, cppcheck) — it bootstraps the flaw
inventory when you have minutes, not hours.

Categories flagged (CWE in parens):
  unbounded-copy      strcpy/strcat/sprintf/gets/scanf-family %s   (CWE-120/787)
  strncpy-noterm      strncpy (may leave dst non-NUL-terminated)   (CWE-170)
  format-string       printf-family with a non-literal format      (CWE-134)
  snprintf-truncation snprintf/vsnprintf whose return is discarded  (CWE-252)
  stack-vla-alloca    alloca / variable-length arrays              (CWE-770)
  int-overflow-mul    malloc(a * b) style size math                (CWE-190)
  command-exec        system/popen/exec* with composed strings     (CWE-78)
  toctou              access()/stat() then open()/fopen()          (CWE-367)
  use-after-free      free(p) then p used before reassignment      (CWE-416)
  double-free         free(p) then free(p) before reassignment     (CWE-415)
  uninitialized-read  TYPE *p; then p used before `p =` / `&p`      (CWE-457)

The last three (use-after-free, double-free, uninitialized-read) are
**windowed-lexical** heuristics: a bounded forward look (≈400 chars, cut at the
next block-closing brace) that catches the common *local* pattern, not the sound
flow analysis a real SAST does — a freed-then-used pointer three functions away, or
a var initialized in another branch, is out of scope. They are questions, not
proofs. (No unchecked-malloc/CWE-690: use-after-NULL needs whole-program flow this
grep can't do honestly.)

Multi-line robustness: the sink checks scan the whole (comment-masked) file, so a
call split across lines — `malloc(a *\\n  b)`, `sscanf(u,\\n "%s", x)` — is not
missed by a per-line regex.

Usage:
  scan_c_flaws.py PATH [PATH ...] [--json] [--self-test]
Exit: 0 always (this is an inventory, not a gate) unless --strict (then 1 if hits).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

CHECKS = [
    ("unbounded-copy", "CWE-120",
     re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(")),
    ("unbounded-copy", "CWE-120",
     re.compile(r"\b(scanf|fscanf|sscanf|vscanf|vfscanf|vsscanf)\s*\([^)]*%s")),
    ("strncpy-noterm", "CWE-170",
     re.compile(r"\bstrncpy\s*\(")),
    ("stack-vla-alloca", "CWE-770",
     re.compile(r"\balloca\s*\(")),
    ("int-overflow-mul", "CWE-190",
     re.compile(r"\b(malloc|calloc|realloc)\s*\([^;)]*[*][^;)]*\)")),
    ("command-exec", "CWE-78",
     re.compile(r"\b(system|popen|execl|execlp|execv|execvp)\s*\(")),
    ("toctou", "CWE-367",
     re.compile(r"\b(access|stat|lstat)\s*\(")),
]

# printf-family: name -> index of the *format-string* argument. The format is
# NOT always arg 0 — it follows the stream (fprintf), buffer (sprintf), size
# (snprintf), or priority/eval (syslog/err). Flagging arg 0 blindly produces a
# false positive on every `fprintf(stderr, "literal", ...)` — which is what
# buried the real findings when this scanner was first run against lsof
# (828 false positives). We flag only when the format-position arg is a
# *non-literal* (doesn't start with a string literal). (LESSONS #2)
FORMAT_FUNCS = {
    "printf": 0, "vprintf": 0, "warn": 0, "warnx": 0, "vwarn": 0,
    "fprintf": 1, "vfprintf": 1, "dprintf": 1, "sprintf": 1, "vsprintf": 1,
    "syslog": 1, "vsyslog": 1, "err": 1, "errx": 1, "asprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
}
_FMT_CALL = re.compile(r"\b(" + "|".join(FORMAT_FUNCS) + r")\s*\(")
_SNPRINTF = re.compile(r"\b(v?snprintf)\s*\(")
_FREE = re.compile(r"\bfree\s*\(\s*(\*?\s*\w+)\s*\)")
# A local pointer declared with no initializer: `TYPE *p;` on its own line.
_UNINIT_DECL = re.compile(
    r"(?m)^[ \t]*"
    r"(?:const |volatile |unsigned |signed )*"
    r"(?:void|char|short|int|long|float|double|size_t|ssize_t|wchar_t|"
    r"u?int(?:8|16|32|64|ptr|max)_t|struct \w+|enum \w+|union \w+|\w+_t)"
    r"\s+\*\s*(\w+)\s*;[ \t]*$")

_WINDOW = 400  # forward look for the free/uninit heuristics


def _lineno(src, pos):
    return src.count("\n", 0, pos) + 1


def _line_text(orig_lines, line):
    return orig_lines[line - 1].strip()[:120] if 0 <= line - 1 < len(orig_lines) else ""


def _call_args(src, open_paren):
    """Return the top-level comma-separated argument strings of a call whose
    '(' is at index `open_paren`, plus the index just past the ')'. Skips string
    and char literals and nested parens. Best-effort on an unbalanced tail."""
    depth, args, cur, j, n = 0, [], [], open_paren, len(src)
    while j < n:
        c = src[j]
        if c in '"\'':
            quote = c
            cur.append(c); j += 1
            while j < n and src[j] != quote:
                if src[j] == "\\" and j + 1 < n:
                    cur.append(src[j]); cur.append(src[j + 1]); j += 2; continue
                cur.append(src[j]); j += 1
            if j < n:
                cur.append(src[j]); j += 1
            continue
        if c == "(":
            depth += 1
            if depth > 1:
                cur.append(c)
            j += 1; continue
        if c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args, j + 1
            cur.append(c); j += 1; continue
        if c == "," and depth == 1:
            args.append("".join(cur)); cur = []; j += 1; continue
        cur.append(c); j += 1
    args.append("".join(cur))
    return args, n


def _mask_c_comments(src):
    """Return src with // and /* */ comment contents (delimiters included)
    replaced by spaces, preserving every byte offset and newline so line
    numbers in the masked text match the original. String and char literals
    are left intact — a `//` inside "http://x" is not a comment, and the
    format-string pass needs the literals to tell a constant format from a
    variable one. C block comments do not nest.

    This replaces the old skip-lines-starting-with-*-or-// heuristic, which
    also swallowed real code: `*out = malloc(a * b);` (pointer-deref
    assignment) begins with `*` and was silently never scanned — a false
    negative, the one direction a Phase-0 security scanner must not err in
    (LESSONS #6)."""
    out = []
    i, n = 0, len(src)
    while i < n:
        two = src[i : i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if two == "/*":
            out.append("  ")
            i += 2
            while i < n and src[i : i + 2] != "*/":
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append("  ")
                i += 2
            continue
        c = src[i]
        if c in "\"'":
            out.append(c)
            i += 1
            while i < n and src[i] != c:
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i]); out.append(src[i + 1])
                    i += 2
                    continue
                out.append(src[i])
                i += 1
            if i < n:
                out.append(c)
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _scan_format_strings(src, orig_lines):
    hits = []
    for m in _FMT_CALL.finditer(src):
        name = m.group(1)
        args, _end = _call_args(src, m.end() - 1)
        idx = FORMAT_FUNCS[name]
        if idx >= len(args):
            continue  # too few args to tell; don't cry wolf
        fmt = args[idx].strip()
        # Literal format (starts with a string, or a wide/utf literal) is safe.
        if fmt.startswith(('"', 'L"', 'u8"', 'u"', 'U"')):
            continue
        if not fmt:
            continue
        lineno = _lineno(src, m.start())
        hits.append({"line": lineno, "category": "format-string", "cwe": "CWE-134",
                     "text": (name + "(" + args[idx].strip())[:120]})
    return hits


def _scan_snprintf_truncation(src, orig_lines):
    """Flag snprintf/vsnprintf whose return value is DISCARDED — a bare
    statement — so a truncated write goes undetected (CWE-252). We look at the
    first non-space char before the call: a statement boundary (`;`, `{`, `}`)
    or a control-flow `)` (as in `if (x) snprintf(...);`) means the result is
    thrown away; `=`, `(`, `,`, an operator, or `return` means it is used."""
    hits = []
    for m in _SNPRINTF.finditer(src):
        j = m.start() - 1
        while j >= 0 and src[j] in " \t\r\n":
            j -= 1
        prev = src[j] if j >= 0 else ";"   # start-of-file behaves like a statement start
        if prev in ";{})":
            line = _lineno(src, m.start())
            hits.append({"line": line, "category": "snprintf-truncation", "cwe": "CWE-252",
                         "text": _line_text(orig_lines, line)})
    return hits


def _var_regexes(var):
    ev = re.escape(var)
    return (
        re.compile(r"\bfree\s*\(\s*\*?\s*" + ev + r"\s*\)"),   # re-free of var
        # a WRITE of `var` (not `*var =` deref-write, not `p->var =` member-write,
        # both of which READ var) — a genuine reassignment makes the pointer safe.
        re.compile(r"(?<![\w.>&*])" + ev + r"\s*=(?!=)"),
        re.compile(r"&\s*" + ev + r"\b"),                     # address taken → callee may fill
        re.compile(r"(?<![\w])" + ev + r"(?![\w])"),          # any use of var
    )


def _scan_use_after_free(src, orig_lines):
    hits = []
    for m in _FREE.finditer(src):
        var = m.group(1).replace("*", "").strip()
        if not var or var == "NULL" or var.isdigit():
            continue
        w = src[m.end(): m.end() + _WINDOW]
        cut = re.search(r"\n[ \t]*\}", w)   # stop at the enclosing block's close
        if cut:
            w = w[: cut.start()]
        refree, write, addr, use = _var_regexes(var)
        r_, wr, ad, us = refree.search(w), write.search(w), addr.search(w), use.search(w)
        stop = min([x.start() for x in (wr, ad) if x], default=len(w) + 1)
        if r_ and r_.start() < stop:
            line = _lineno(src, m.end() + r_.start())
            hits.append({"line": line, "category": "double-free", "cwe": "CWE-415",
                         "text": _line_text(orig_lines, line)})
        elif us and us.start() < stop:
            line = _lineno(src, m.end() + us.start())
            hits.append({"line": line, "category": "use-after-free", "cwe": "CWE-416",
                         "text": _line_text(orig_lines, line)})
    return hits


def _scan_uninit(src, orig_lines):
    """Uninitialized POINTER read: `TYPE *p;` (no initializer), then p is used
    before any `p =` (write) or `&p` (address taken → a callee fills it). Scoped
    to pointers — a wild-pointer read is the high-value case; scalar uninit is
    lower-stakes and much noisier."""
    hits = []
    for m in _UNINIT_DECL.finditer(src):
        var = m.group(1)
        w = src[m.end(): m.end() + _WINDOW]
        cut = re.search(r"\n[ \t]*\}", w)
        if cut:
            w = w[: cut.start()]
        _rf, write, addr, use = _var_regexes(var)
        wr, ad, us = write.search(w), addr.search(w), use.search(w)
        stop = min([x.start() for x in (wr, ad) if x], default=len(w) + 1)
        if us and us.start() < stop:
            line = _lineno(src, m.end() + us.start())
            hits.append({"line": line, "category": "uninitialized-read", "cwe": "CWE-457",
                         "text": _line_text(orig_lines, line)})
    return hits


def scan_text(src):
    # Mask comments ONCE, then scan the masked text WHOLE-FILE (a sink call can
    # span lines): commented-out code can't fire (no noise), and real code that
    # merely looks comment-like (`*out = ...`) is still scanned (no false
    # negatives). Line numbers survive masking (newlines preserved).
    masked = _mask_c_comments(src)
    orig_lines = src.splitlines()
    hits = []
    for cat, cwe, rx in CHECKS:
        for m in rx.finditer(masked):
            line = _lineno(masked, m.start())
            hits.append({"line": line, "category": cat, "cwe": cwe,
                         "text": _line_text(orig_lines, line)})
    hits.extend(_scan_format_strings(masked, orig_lines))
    hits.extend(_scan_snprintf_truncation(masked, orig_lines))
    hits.extend(_scan_use_after_free(masked, orig_lines))
    hits.extend(_scan_uninit(masked, orig_lines))
    hits.sort(key=lambda h: (h["line"], h["category"]))
    return hits


def iter_c_files(paths):
    for p in paths:
        if os.path.isfile(p) and p.endswith((".c", ".h")):
            yield p
        elif os.path.isdir(p):
            for root, _d, files in os.walk(p):
                for f in files:
                    if f.endswith((".c", ".h")):
                        yield os.path.join(root, f)


def run(paths, as_json, strict):
    all_hits, by_cat = [], {}
    for path in sorted(set(iter_c_files(paths))):
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for h in scan_text(src):
            h["file"] = path
            all_hits.append(h)
            by_cat[h["category"]] = by_cat.get(h["category"], 0) + 1

    if as_json:
        print(json.dumps({"total": len(all_hits), "by_category": by_cat, "hits": all_hits}, indent=2))
    else:
        for h in all_hits:
            print(f"{h['file']}:{h['line']}  [{h['category']}/{h['cwe']}]  {h['text']}")
        print(f"\n{len(all_hits)} potential flaw site(s); by category:")
        for cat, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
            print(f"    {n:4}  {cat}")
        print("\nTriage each: does the Rust port close it? Record confirmed fixes in DIVERGENCES.md.")
    return 1 if (strict and all_hits) else 0


SELF_TEST_C = r'''
#include <stdio.h>
void bad(char *u, char *dynfmt, char **dst) {
    char buf[16];
    strcpy(buf, u);                     /* unbounded-copy */
    *dst = strcpy(buf, u);              /* unbounded-copy: deref-assign line
                                           starts with '*' but IS code */
    r = "http://x"; q = strcat(p, u);   /* unbounded-copy; the // inside the
                                           string literal is NOT a comment */
    sscanf(u, "%s", buf);               /* unbounded-copy: scanf-family %s */
    strncpy(buf, u, 8);                 /* strncpy-noterm */
    printf(u);                          /* format-string: arg 0 non-literal */
    fprintf(stderr, "literal %s\n", u); /* SAFE: format arg is a literal */
    fprintf(stderr, dynfmt, u);         /* format-string: arg 1 non-literal */
    int cap = snprintf(buf, 8, "%d", 1);/* SAFE snprintf: return is captured */
    snprintf(buf, 8, "%s", u);          /* snprintf-truncation: return discarded */
    char *p = malloc(n * width);        /* int-overflow-mul */
    *dst = malloc(n * m);               /* int-overflow-mul: deref-assign */
    system(cmd);                        /* command-exec */
    if (access(path, R_OK)) {}          /* toctou */
    char *d1 = grab(); free(d1); free(d1);   /* double-free of d1 */
    char *d2 = grab(); free(d2); sink(d2);   /* use-after-free: d2 read after free */
    char *d3 = grab(); free(d3); d3 = 0;     /* SAFE: reassigned after free */
    int *wild;                          /* uninitialized pointer... */
    *wild = 7;                          /* ...deref before write: uninitialized-read */
    char *set; set = pick(); *set = 1;  /* SAFE: assigned before deref */
    /* strcpy(x, y);  in a comment - must be ignored */
    /* printf(old_fmt);  commented-out format call - must be ignored */
    // fprintf(stderr, dynfmt, u);      commented-out too - must be ignored
}
'''


def _self_test():
    hits = scan_text(SELF_TEST_C)
    cats = {h["category"] for h in hits}
    n = lambda c: sum(1 for h in hits if h["category"] == c)
    fmt_hits = [h for h in hits if h["category"] == "format-string"]
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    check("flags unbounded-copy", "unbounded-copy" in cats)
    check("flags format-string", "format-string" in cats)
    check("flags int-overflow-mul", "int-overflow-mul" in cats)
    check("flags command-exec", "command-exec" in cats)
    check("flags toctou", "toctou" in cats)
    # Comment masking, both directions: commented-out strcpy must NOT count,
    # while the deref-assign line (`*dst = strcpy(...)`, starts with '*'), the
    # call after a "//"-containing string literal, and the scanf-family %s
    # MUST. 4 real copy sites.
    check("copy sites: deref-assign + string-'//' + sscanf scanned, comment ignored",
          n("unbounded-copy") == 4)
    check("deref-assign malloc line scanned (2 mul sites)", n("int-overflow-mul") == 2)
    # The format-string fix (LESSONS #2): only NON-LITERAL format args flag.
    check("format-string flags exactly the 2 real non-literal calls "
          "(literal + commented-out calls ignored)", len(fmt_hits) == 2)
    check("literal-format fprintf/snprintf NOT flagged",
          not any("literal" in h["text"] or '"%d"' in h["text"] for h in fmt_hits))

    # --- new categories (P1 #6) ---
    check("flags strncpy-noterm", n("strncpy-noterm") == 1)
    # snprintf-truncation: the discarded call is flagged; the captured `cap =` is not
    check("snprintf-truncation flags the discarded call", n("snprintf-truncation") >= 1)
    check("snprintf with a captured return is NOT flagged as truncation",
          not any(h["category"] == "snprintf-truncation" and "cap" in h["text"] for h in hits))
    check("flags double-free (free(d1); free(d1))", n("double-free") == 1)
    check("flags use-after-free (d2 used after free)",
          any(h["category"] == "use-after-free" and "d2" in h["text"] for h in hits))
    check("free-then-reassign (d3 = 0) is NOT flagged",
          not any("d3" in h["text"] for h in hits if h["category"] in ("use-after-free", "double-free")))
    check("flags uninitialized-read (wild pointer deref before write)",
          any(h["category"] == "uninitialized-read" and "wild" in h["text"] for h in hits))
    check("pointer assigned before deref (set) is NOT flagged uninitialized",
          not any(h["category"] == "uninitialized-read" and "set" in h["text"] for h in hits))

    # --- multi-line robustness: a call split across lines is still caught ---
    ml = "void f(){ char *p = malloc(count *\n                 width); }"
    check("whole-file scan catches a multi-line malloc(a *\\n b)",
          any(h["category"] == "int-overflow-mul" for h in scan_text(ml)))

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any hit (for a gate)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.paths:
        ap.print_usage(sys.stderr)
        print("error: give at least one PATH, or --self-test", file=sys.stderr)
        return 2
    return run(args.paths, args.json, args.strict)


if __name__ == "__main__":
    sys.exit(main())
