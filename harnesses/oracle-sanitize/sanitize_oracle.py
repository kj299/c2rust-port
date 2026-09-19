#!/usr/bin/env python3
"""Oracle-sanitize — the C side of the differential is C code the port WROTE,
and nothing was checking it.

Why (LESSONS #40): every port builds a driver around the vendored C so the
differential has something to execute — `ports/cjson/oracle/driver.c` plus
`cjson_modes.c`, ~1000 lines of hand-written C by the cJSON port's fourteenth
module. That code does manual buffer sizing and manual ownership juggling
against an API that splits ownership across a return value, and it is compiled
WITHOUT sanitizers, because the oracle must behave like the shipped library.

A memory error in there does not change stdout. So the differential stays green,
the fuzzer stays green, and the Rust-side sanitizer gate never looks at C.
`ports/cjson/oracle` was in exactly that position for fourteen modules: unchecked,
and clean only by luck and review. The gap was found the way these things are
found — a probe program leaked, LeakSanitizer named the line, and the same
ownership rule was three lines away in the driver.

Mechanics: the PORT builds a sanitized twin of its own oracle (same sources,
`-fsanitize=address,undefined` plus leak detection) and hands the binary here.
This harness drives every matrix case through it and fails on any sanitizer
report. It compares nothing — `diff_run.py` already does that — it only asks
whether the oracle itself is memory-clean over the same inputs.

Fail-closed choices worth stating:
  * A binary that produces no sanitizer output on ZERO cases proves nothing
    (LESSONS #18's 0-of-0 shape). An empty case set is an error.
  * The sanitized binary must actually be sanitized: a build that silently
    dropped `-fsanitize` would report clean forever. `--require-instrumented`
    (default on) checks the binary for the sanitizer runtime and refuses one
    that has none, so pointing this at the PLAIN oracle fails loudly.
  * A case's exit status is ignored on purpose. Oracles legitimately exit
    nonzero (a parse failure is rc 1); the verdict is the sanitizer's, not the
    program's.

Usage:
  sanitize_oracle.py --oracle <sanitized-binary> --matrix <m.json> [--matrix ...]
                     [--timeout SECS] [--json] [--no-require-instrumented]
  sanitize_oracle.py --self-test
Exit: 0 = every case ran clean; 1 = a sanitizer reported, or the setup is unsound.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile

# Substrings that mean a sanitizer spoke. UBSan's is lowercase prose rather than
# a banner, which is why it is matched separately — an earlier draft looked only
# for "Sanitizer" and would have ignored every UBSan finding.
REPORT_MARKERS = (
    "AddressSanitizer",
    "LeakSanitizer",
    "ThreadSanitizer",
    "MemorySanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)

# Symbols the instrumentation leaves in the binary. Checked as bytes so this
# works without nm/objdump being installed.
INSTRUMENT_MARKERS = (b"__asan_", b"__ubsan_", b"__msan_", b"__tsan_", b"__sanitizer_")


def case_stdin(case):
    """A matrix case's stdin as raw bytes — `stdin_b64` wins, then `stdin`."""
    if "stdin_b64" in case:
        return base64.b64decode(case["stdin_b64"], validate=True)
    value = case.get("stdin", "")
    return value.encode() if isinstance(value, str) else bytes(value)


def load_cases(paths):
    cases = []
    for path in paths:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        rows = data["case"] if isinstance(data, dict) and "case" in data else data
        for row in rows:
            cases.append((os.path.basename(path), row))
    return cases


def is_instrumented(path):
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError:
        return False
    return any(m in blob for m in INSTRUMENT_MARKERS)


def run_case(oracle, case, timeout):
    """Run one case. Returns the sanitizer's complaint, or None when clean."""
    env = dict(os.environ)
    # Leaks are the whole point for an oracle that hands ownership around, and
    # they are off by default in some builds.
    env["ASAN_OPTIONS"] = "detect_leaks=1:" + env.get("ASAN_OPTIONS", "")
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:" + env.get("UBSAN_OPTIONS", "")
    try:
        proc = subprocess.run(
            [oracle] + list(case.get("args", [])),
            input=case_stdin(case),
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"timed out after {timeout}s"
    err = proc.stderr.decode("utf-8", "replace")
    if any(m in err for m in REPORT_MARKERS):
        return "\n".join(err.strip().splitlines()[:12])
    return None


def check(oracle, matrices, timeout, require_instrumented=True):
    """Returns (findings, total). Raises SystemExit on an unsound setup."""
    if not os.path.exists(oracle):
        sys.exit(f"error: sanitized oracle {oracle!r} does not exist — build it first")
    if require_instrumented and not is_instrumented(oracle):
        sys.exit(
            f"error: {oracle!r} carries no sanitizer runtime. A clean report from an "
            "uninstrumented binary is meaningless; build it with -fsanitize=address,undefined "
            "(or pass --no-require-instrumented if you know better)"
        )
    cases = load_cases(matrices)
    if not cases:
        sys.exit("error: zero matrix cases — a clean run over nothing proves nothing")
    findings = []
    for label, case in cases:
        complaint = run_case(oracle, case, timeout)
        if complaint is not None:
            findings.append({"matrix": label, "case": case.get("name", "?"),
                             "report": complaint})
    return findings, len(cases)


def _self_test():
    ok = True

    def report(label, passed):
        nonlocal ok
        print(f"{'PASS' if passed else 'FAIL'}  {label}")
        ok = ok and passed

    tmp = tempfile.mkdtemp()
    # A program that leaks whatever it reads, and one that does not. Kept
    # deliberately dull: a fixture too clever to compile turns this whole
    # self-test into a SKIP, which is the failure mode the harness is about.
    leaky_c = (
        "#include <stdlib.h>\n#include <stdio.h>\n"
        "int main(void) {\n"
        "  char buf[64];\n"
        "  size_t n = fread(buf, 1, sizeof buf, stdin);\n"
        "  if (n > 0) {\n"
        "    char *p = (char *)malloc(32);\n"
        "    if (p != NULL) { p[0] = buf[0]; fputc(p[0], stdout); }\n"
        "  }\n"
        "  return 0;\n"
        "}\n")
    clean_c = (
        "#include <stdio.h>\n"
        "int main(void) {\n"
        "  char b[8];\n"
        "  size_t n = fread(b, 1, sizeof b, stdin);\n"
        "  fputc(n ? 'k' : 'e', stdout);\n"
        "  return 0;\n"
        "}\n")
    src = os.path.join(tmp, "leaky.c")
    clean_src = os.path.join(tmp, "clean.c")
    with open(src, "w", encoding="utf-8") as f:
        f.write(leaky_c)
    with open(clean_src, "w", encoding="utf-8") as f:
        f.write(clean_c)

    cc = os.environ.get("CC", "cc")
    leaky = os.path.join(tmp, "leaky")
    clean = os.path.join(tmp, "clean")
    plain = os.path.join(tmp, "plain")
    san = ["-fsanitize=address,undefined", "-g", "-O0"]

    # Distinguish "no sanitizer-capable compiler" (a legitimate skip) from "the
    # fixture did not compile" (a FAILURE). An earlier draft collapsed the two
    # and reported SKIP on a machine that had just built a sanitized oracle —
    # the same 0-of-0 shape this harness refuses in its own inputs
    # (LESSONS #18/#40).
    probe = subprocess.run([cc, *san, clean_src, "-o", clean],
                           capture_output=True, check=False)
    if probe.returncode != 0:
        print("SKIP  no sanitizer-capable C compiler; harness logic untested here")
        return 0
    build = subprocess.run([cc, *san, src, "-o", leaky], capture_output=True, check=False)
    if build.returncode != 0:
        print("FAIL  the self-test's own leaky fixture did not compile — "
              "this is a broken test, not a missing toolchain")
        print(build.stderr.decode("utf-8", "replace")[:800])
        return 1
    subprocess.run([cc, "-O0", clean_src, "-o", plain], capture_output=True, check=True)

    matrix = os.path.join(tmp, "m.json")
    with open(matrix, "w", encoding="utf-8") as f:
        json.dump([{"name": "leaks", "args": [], "stdin": "abc"}], f)
    empty = os.path.join(tmp, "empty.json")
    with open(empty, "w", encoding="utf-8") as f:
        json.dump([], f)
    b64 = os.path.join(tmp, "b64.json")
    with open(b64, "w", encoding="utf-8") as f:
        json.dump([{"name": "raw", "args": [], "stdin_b64": base64.b64encode(b"\xff\x00\xfe").decode()}], f)

    findings, total = check(leaky, [matrix], 30)
    report("a leaking oracle is a finding", len(findings) == 1 and total == 1)
    report("the finding names the sanitizer",
           bool(findings) and "Sanitizer" in findings[0]["report"])

    findings, total = check(clean, [matrix], 30)
    report("a clean oracle reports nothing", findings == [] and total == 1)

    findings, _ = check(clean, [b64], 30)
    report("a stdin_b64 case reaches the child", findings == [])

    rc = subprocess.run([sys.executable, __file__, "--oracle", plain, "--matrix", matrix],
                        capture_output=True, check=False)
    report("an UNINSTRUMENTED binary is refused, not reported clean",
           rc.returncode == 1 and b"no sanitizer runtime" in rc.stderr)

    rc = subprocess.run([sys.executable, __file__, "--oracle", clean, "--matrix", empty],
                        capture_output=True, check=False)
    report("an empty matrix is refused (0-of-0 proves nothing)",
           rc.returncode == 1 and b"zero matrix cases" in rc.stderr)

    rc = subprocess.run([sys.executable, __file__, "--oracle",
                         os.path.join(tmp, "nope"), "--matrix", matrix],
                        capture_output=True, check=False)
    report("a missing oracle is an error, not a skip", rc.returncode == 1)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="path to a SANITIZED build of the port's C oracle")
    ap.add_argument("--matrix", action="append", default=[],
                    help="matrix JSON (repeatable); every case is executed")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-require-instrumented", dest="require_instrumented",
                    action="store_false", default=True)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.oracle or not args.matrix:
        ap.error("--oracle and at least one --matrix are required")

    findings, total = check(args.oracle, args.matrix, args.timeout,
                            args.require_instrumented)
    if args.json:
        print(json.dumps({"tool": "oracle-sanitize", "cases": total,
                          "findings": findings}, indent=1))
    else:
        for f in findings:
            print(f"SANITIZER  {f['matrix']} :: {f['case']}")
            for line in f["report"].splitlines():
                print(f"    {line}")
        verdict = "clean" if not findings else f"{len(findings)} finding(s)"
        print(f"oracle-sanitize: {total} case(s) through the sanitized C oracle — {verdict}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
