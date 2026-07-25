#!/usr/bin/env python3
"""Library (C-ABI) differential harness — the function-level analogue of
diff_run.py for a *shared library* instead of an executable.

diff_run.py drives argv/stdin and compares stdout+exit; that shape does not fit a
C-ABI library, which has no CLI. This harness loads the C `.so`/`.dylib` and the
Rust `cdylib` **interchangeably** through ctypes and, for each vector in a
function-vector suite, calls the named function on BOTH with identical arguments
and compares the observable result. Modeled on MIT-LL's public `cando` differ
(DARPA-TRACTOR): the unit of comparison is a function call, and the verdict covers
the **return value AND the mutated output state** (the bytes the function wrote
into caller-provided buffers) — the library analogue of diff_run's "stdout AND
exit code" rule (LESSONS #4).

Fail-closed, like the executable differential:
  * Each call runs in a **forked child process**, so a segfault/abort in a C-ABI
    function is a CRASH *finding*, never a harness death. The parent reads the
    result CONCURRENTLY with the child (draining the pipe as it is written, so an
    arbitrarily large output buffer streams through instead of dead-locking) and
    reaps a hung child by escalating SIGTERM→SIGKILL under a bounded grace, so a
    signal-ignoring or looping C call cannot wedge the harness (LESSONS #1/#6).
  * A rust-side CRASH or TIMEOUT is a hard verdict: never MATCH, never excusable
    by the ledger (a crash/hang is not fidelity). A C-side-only crash/hang while
    the Rust returns cleanly is an ordinary DIVERGE to triage — "the C faults on
    this input, the Rust handles it safely" is a legitimate fix-of-C-defect.

Divergences are triaged, not blindly failed, through the SAME ledger as diff_run
(`DIVERGENCES.md`): `- [x] <name>: <why>` suppresses by name; `- [x] <name>
[sha256:<12-hex>]: <why>` pins one accepted divergence so a *changed* divergence
in a ledgered vector fails again (LESSONS #8). The ledger parser is reused from
diff_run, so the two harnesses share one triage format.

Vector suite (JSON or TOML) — a list of vectors, each:

  {
    "name": "adler32-empty",       # unique; becomes a report/ledger key (no '/')
    "function": "adler32",         # logical function name (see --c-symbols)
    "returns": "size_t",           # REQUIRED. int|i32|uint|long|size_t|double|float
                                   #  |cstr (compare the pointed-to string)
                                   #  |ptr  (compare position within a tracked buffer
                                   #         by offset; else only NULL vs non-NULL)
                                   #  |void ; add "returns_ignore": true to skip it.
                                   #  Declare the width that matches the C signature —
                                   #  a too-narrow type truncates on BOTH sides.
    "args": [
      {"type": "cstr",   "value": "hello", "id": "s"},  # NUL-terminated input string
      {"type": "int",    "value": 5},                    # scalar in
      {"type": "outbuf", "size": 16, "id": "dst"},       # buffer the fn writes → compared
      {"type": "inoutbuf", "size": 16, "value": "..", "id": "io"}  # seeded + compared
    ],
    "timeout": 10                  # optional per-vector liveness cap (seconds)
  }

Return-value fidelity: floats are compared by IEEE-754 bit pattern (so -0.0 ≠ 0.0
and NaN == NaN); a pointer return that lands inside a tracked input/output buffer
is compared by (buffer-id, offset) — portable across the two libraries, unlike the
raw address — which is what makes strchr/memchr/strstr-style "position" returns
comparable; only a pointer outside every tracked buffer degrades to NULL-vs-nonNULL.

The C and Rust libraries need not export the same symbol name for a logical
function (a Rust cdylib often exports `rs_adler32` or a `#[no_mangle]` alias):
`--c-symbols`/`--rust-symbols` map logical name → actual exported symbol per side.

Scope (v1, honest): scalar/string/byte inputs, caller-write output buffers, and
the return value — the bulk of a C-ABI surface. Structs-by-value, function-pointer
callbacks, and external side effects (files/env) are not yet modeled; add them as a
port demands and record it in LESSONS. Uses fork, so Linux/macOS `.so`/`.dylib`
today (on macOS this sets OBJC_DISABLE_INITIALIZE_FORK_SAFETY for the children so
a framework-linked dylib doesn't abort every fork); a Windows `.dll` path (no fork)
is a documented cross-platform to-do.

Usage:
  lib_diff.py --c-lib PATH --rust-lib PATH --vectors FILE [--ledger DIVERGENCES.md]
              [--c-symbols FILE] [--rust-symbols FILE] [--timeout SEC] [--json]
  lib_diff.py --self-test
Exit: 0 = all MATCH or all divergences ledgered; 1 = an unexplained DIVERGE, a
CRASH, a TIMEOUT, or a call ERROR.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import multiprocessing as mp
import os
import queue as _queue
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "differential"))
import diff_run as _D  # noqa: E402  (shared provenance_stamp)
import time

# On macOS, forking after the Objective-C runtime initializes aborts the child;
# opt the children out so a framework-linked dylib doesn't turn every call into a
# spurious CRASH. Set before any fork; harmless on Linux. (Must precede fork.)
os.environ.setdefault("OBJC_DISABLE_INITIALIZE_FORK_SAFETY", "YES")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "differential"))
import diff_run as D  # noqa: E402  (reuse load_ledger + case-name validation)


_SCALAR = {
    "int": ctypes.c_int, "i32": ctypes.c_int32, "uint": ctypes.c_uint,
    "long": ctypes.c_long, "size_t": ctypes.c_size_t,
    "double": ctypes.c_double, "float": ctypes.c_float,
}
_FLOATS = {"double", "float"}
_RESTYPE = {**_SCALAR, "ptr": ctypes.c_void_p, "cstr": ctypes.c_char_p, "void": None}
DEFAULT_TIMEOUT = 10
_REAP_GRACE = 2.0        # bounded wait after signalling a hung child, before escalating
_POLL = 0.05             # how often the parent checks for a result / child death


def load_vectors(path):
    """Load + validate the vector suite (reusing diff_run's name-safety check:
    a name becomes a ledger/report key, so a path separator is rejected)."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        vectors = data["vector"] if isinstance(data, dict) and "vector" in data else data
    else:
        try:
            import tomllib
        except ModuleNotFoundError:
            sys.exit("error: TOML vectors need Python 3.11+ (tomllib); use a .json file")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        vectors = data.get("vector", data if isinstance(data, list) else [])
    if not vectors:
        sys.exit(f"error: vector suite {path!r} loaded 0 vectors — empty or mis-keyed "
                 "(expected `[[vector]]` / a top-level list). A differential over 0 "
                 "vectors cannot pass (LESSONS #6, fail closed).")
    D._validate_matrix(vectors)  # names are non-empty, no separators/traversal
    for v in vectors:
        if not v.get("function"):
            sys.exit(f"error: vector {v.get('name')!r} needs a `function` name")
        if "returns" not in v:
            sys.exit(f"error: vector {v['name']!r} needs a `returns` type (declare the "
                     "width matching the C signature; a too-narrow type truncates both sides)")
    return vectors


def _as_bytes(v):
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return v.encode("utf-8")
    if isinstance(v, list):
        return bytes(v)
    raise ValueError(f"cannot convert {v!r} to bytes")


def _normalize_ret(ret_type, raw, tracked, ignore):
    """Turn a raw ctypes return into a portable, comparable value. `tracked` is a
    list of (id, base_addr, size) for every buffer we own, so a pointer return
    that lands inside one is compared by position, not by its (non-portable)
    absolute address."""
    if ignore or ret_type == "void":
        return None
    if ret_type == "ptr":
        if not raw:
            return "NULL"
        for label, base, size in tracked:
            if base <= raw < base + size:
                return ["offset", label, raw - base]
        return "PTR"  # a real address outside every buffer we can localize
    if ret_type == "cstr":
        return raw  # bytes: the pointed-to string content (portable)
    if ret_type in _FLOATS:
        # Bit pattern, not float ==, so -0.0 ≠ 0.0 and identical NaNs compare equal.
        return struct.pack("<f" if ret_type == "float" else "<d", raw).hex()
    return raw  # int / size_t / …


def _do_call(lib_path, symbol_map, vector):
    """Marshal args, call the function once, return (ret_norm, outputs). Runs
    inside the forked child — a fault here dies as a signal the parent reads."""
    lib = ctypes.CDLL(lib_path) if lib_path else ctypes.CDLL(None)
    logical = vector["function"]
    sym = symbol_map.get(logical, logical)
    fn = getattr(lib, sym)  # AttributeError if the symbol is absent → ERROR

    argtypes, cargs, outbufs, tracked = [], [], [], []
    for i, a in enumerate(vector.get("args", [])):
        t = a["type"]
        label = a.get("id", f"arg{i}")
        if t in _SCALAR:
            argtypes.append(_SCALAR[t])
            cargs.append(float(a["value"]) if t in _FLOATS else int(a["value"]))
            continue
        if t == "cstr":
            buf = ctypes.create_string_buffer(_as_bytes(a["value"]))  # NUL-terminated
        elif t in ("outbuf", "inoutbuf"):
            size = int(a["size"])
            buf = (ctypes.create_string_buffer(_as_bytes(a.get("value", "")), size)
                   if t == "inoutbuf" else ctypes.create_string_buffer(size))
            outbufs.append((label, buf))
        else:
            raise ValueError(f"unknown arg type {t!r} in vector {vector['name']!r}")
        argtypes.append(ctypes.c_char_p)
        cargs.append(buf)
        tracked.append((label, ctypes.addressof(buf), ctypes.sizeof(buf)))

    fn.argtypes = argtypes
    ret_type = vector.get("returns", "int")
    if ret_type not in _RESTYPE:
        raise ValueError(f"unknown return type {ret_type!r} in vector {vector['name']!r}")
    fn.restype = _RESTYPE[ret_type]
    raw = fn(*cargs)

    ret_norm = _normalize_ret(ret_type, raw, tracked, bool(vector.get("returns_ignore")))
    outputs = {oid: buf.raw for oid, buf in outbufs}
    return ret_norm, outputs


def _child(q, lib_path, symbol_map, vector):
    try:
        ret, outputs = _do_call(lib_path, symbol_map, vector)
        q.put(("ok", ret, outputs, ""))
    except BaseException as e:  # noqa: BLE001 — report any failure, don't die silently
        q.put(("error", None, {}, f"{type(e).__name__}: {e}"))


def _res(status, ret=None, outputs=None, detail=""):
    return {"status": status, "ret": ret, "outputs": outputs or {}, "detail": detail}


def invoke(lib_path, symbol_map, vector, default_timeout=DEFAULT_TIMEOUT):
    """Call one vector in a forked child and classify the outcome as
    ok / crash / timeout / error. The result is read concurrently with the child
    (so large output buffers stream through instead of dead-locking the feeder),
    a fast crash/exit is detected promptly, and a hung child is reaped with a
    SIGTERM→SIGKILL escalation so it can never wedge the harness."""
    timeout = vector.get("timeout", default_timeout)
    ctx = mp.get_context("fork")
    q = ctx.Queue()
    p = ctx.Process(target=_child, args=(q, lib_path, symbol_map or {}, vector))
    p.start()

    deadline = time.monotonic() + timeout
    outcome, result = None, None
    while outcome is None:
        try:
            result = q.get(timeout=_POLL)   # drains the pipe as the feeder writes
            outcome = "result"
        except _queue.Empty:
            if not p.is_alive():            # child exited without (more) output
                try:
                    result = q.get_nowait()
                    outcome = "result"
                except (_queue.Empty, EOFError, OSError, ValueError):
                    outcome = "exited"
            elif time.monotonic() >= deadline:
                outcome = "hung"
        except (EOFError, OSError, ValueError):
            outcome = "broken"             # result pipe broke → a child-side fault

    if p.is_alive():
        p.terminate()
        p.join(_REAP_GRACE)
        if p.is_alive():
            p.kill()                       # SIGKILL: cannot be caught or ignored
            p.join(_REAP_GRACE)
    else:
        p.join(_REAP_GRACE)
    code = p.exitcode

    if outcome == "result":
        status, ret, outputs, detail = result
        return _res(status, ret, outputs, detail)
    if outcome == "hung":
        return _res("timeout", detail=f"exceeded {timeout}s")
    if outcome == "broken":
        return _res("error", detail="result pipe broke (child-side fault)")
    # "exited": the child is gone with no usable result
    if code is not None and code < 0:
        return _res("crash", detail=f"killed by signal {-code}")
    return _res("error", detail=f"no result (exit {code})")


def _diff_text(vector, c, r):
    """Human-readable + fingerprint-stable divergence description."""
    lines = []
    if not vector.get("returns_ignore") and c["ret"] != r["ret"]:
        lines.append(f"return: c={c['ret']!r} rust={r['ret']!r}")
    for oid in sorted(set(c["outputs"]) | set(r["outputs"])):
        cv, rv = c["outputs"].get(oid), r["outputs"].get(oid)
        if cv != rv:
            lines.append(f"outbuf[{oid}]: c={cv!r} rust={rv!r}")
    if c["status"] != "ok" or r["status"] != "ok":
        lines.append(f"status: c={c['status']}({c['detail']}) rust={r['status']}({r['detail']})")
    return ("\n".join(lines) + "\n") if lines else ""


def compare_call(vector, c_res, r_res, known):
    """Verdict for one vector, given both sides' outcomes and the ledger map.
    Fidelity is return value AND output state; the rust side fails closed on a
    crash/hang exactly as diff_run's rewrite side does."""
    name = vector["name"]
    text = _diff_text(vector, c_res, r_res)
    fp = hashlib.sha256(text.encode("utf-8")).hexdigest()
    ret_match = bool(vector.get("returns_ignore")) or (c_res["ret"] == r_res["ret"])
    out_match = c_res["outputs"] == r_res["outputs"]
    c_bad = c_res["status"] in ("crash", "timeout")
    pin = known.get(name)

    is_match = (not c_bad) and ret_match and out_match
    if r_res["status"] == "timeout":
        verdict = "TIMEOUT"
    elif r_res["status"] == "crash":
        verdict = "CRASH"
    elif r_res["status"] == "error" or c_res["status"] == "error":
        verdict = "ERROR"
    elif name in known and is_match:
        # A ledger entry ASSERTS this function call diverges (a fix-of-C-defect).
        # If it now MATCHes, the intentional divergence is gone — the fix was
        # likely reverted. Silently passing it as MATCH is what let the adler32
        # exit test go green after the overflow fix was reverted at the library
        # level. An allow-list must assert, not merely suppress (LESSONS #14).
        verdict = "LEDGER-STALE"
        text += (f"ledgered vector {name!r} no longer diverges from the C — the "
                 f"intentional divergence is GONE (fix reverted, or the C changed "
                 f"too). Re-triage: restore the fix, or remove the ledger entry. A "
                 f"ledger asserts a divergence; it does not license a silent MATCH.\n")
    elif is_match:
        verdict = "MATCH"
    elif name in known:
        if pin is not None and not fp.startswith(pin):
            verdict = "DIVERGE"
            text += (f"ledgered fingerprint mismatch: accepted [sha256:{pin}], "
                     f"observed [sha256:{fp[:12]}] — the divergence changed; re-triage\n")
        else:
            verdict = "DIVERGE(ledgered)"
    else:
        verdict = "DIVERGE"

    clean = verdict in ("MATCH", "LEDGER-STALE")
    return {
        "name": name, "verdict": verdict,
        "c_status": c_res["status"], "rust_status": r_res["status"],
        "c_ret": c_res["ret"], "rust_ret": r_res["ret"],
        "fingerprint": None if clean else fp[:12],
        "pinned": pin is not None,
        "diff": None if verdict == "MATCH" else text,
    }


def compare(c_lib, rust_lib, vectors, c_symbols, rust_symbols, ledger,
            default_timeout=DEFAULT_TIMEOUT):
    known = D.load_ledger(ledger)
    results = []
    for v in vectors:
        c_res = invoke(c_lib, c_symbols, v, default_timeout)
        r_res = invoke(rust_lib, rust_symbols, v, default_timeout)
        results.append(compare_call(v, c_res, r_res, known))
    return results


_FAIL_VERDICTS = ("DIVERGE", "CRASH", "TIMEOUT", "ERROR", "LEDGER-STALE")


def _report(results, as_json):
    fails = [r for r in results if r["verdict"] in _FAIL_VERDICTS]
    if as_json:
        print(json.dumps({"provenance": _D.provenance_stamp("lib_diff"),
                          "results": results}, indent=2))
    else:
        for r in results:
            print(f"[{r['verdict']:18}] {r['name']}")
            if r["verdict"] == "DIVERGE(ledgered)" and not r["pinned"]:
                print(f"    (unpinned ledger entry — pin it as `- [x] {r['name']} "
                      f"[sha256:{r['fingerprint']}]: <why>` so a changed divergence fails again)")
            if r["verdict"] in _FAIL_VERDICTS and r["diff"]:
                sys.stdout.write(r["diff"])
        print(f"\n{len(results)} vector(s), {len(fails)} failing "
              f"(DIVERGE/CRASH/TIMEOUT/ERROR)")
        if any(r["verdict"] == "DIVERGE" for r in results):
            print("Triage each DIVERGE: fix the Rust, OR record an intentional "
                  "fix-of-C-defect in the ledger as `- [x] <name> [sha256:<fp>]: <why>`.")
        if any(r["verdict"] in ("CRASH", "TIMEOUT") for r in results):
            print("A rust-side CRASH/TIMEOUT is a hard failure and cannot be ledgered "
                  "(a fault/hang is not fidelity).")
    return fails


def _load_symbols(path):
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    if not isinstance(m, dict):
        sys.exit(f"error: symbol map {path} must be a JSON object logical→symbol")
    return m


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--c-lib", help="the C shared library (.so/.dylib)")
    ap.add_argument("--rust-lib", help="the Rust cdylib under test")
    ap.add_argument("--vectors", help="function-vector suite (.json/.toml)")
    ap.add_argument("--ledger", default="DIVERGENCES.md", help="known-intentional-divergence ledger")
    ap.add_argument("--c-symbols", help="JSON map logical→symbol for the C library")
    ap.add_argument("--rust-symbols", help="JSON map logical→symbol for the Rust library")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"per-vector liveness cap in seconds (default {DEFAULT_TIMEOUT})")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.c_lib and args.rust_lib and args.vectors):
        ap.print_usage(sys.stderr)
        print("error: --c-lib, --rust-lib and --vectors are required", file=sys.stderr)
        return 2

    results = compare(args.c_lib, args.rust_lib, load_vectors(args.vectors),
                      _load_symbols(args.c_symbols), _load_symbols(args.rust_symbols),
                      args.ledger, args.timeout)
    return 1 if _report(results, args.json) else 0


def _self_test():
    """Prove the harness against the system C library (ctypes CDLL(None)) — no
    compiler needed — plus the verdict rule directly. Covers: real marshalling of
    scalars/strings/output buffers, a genuine return divergence (toupper vs
    tolower via the symbol map), position-returning pointers compared by offset
    (strchr vs strrchr), ledger suppression + fingerprint pinning, a rust-side
    crash and hang (fail-closed), a C-only crash (ledgerable), and the exact
    'return AND output state' rule (incl. a load-bearing returns_ignore)."""
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    def verdict(vector, c_syms=None, r_syms=None, ledger=None, timeout=3):
        known = D.load_ledger(ledger)
        c = invoke(None, c_syms or {}, vector, timeout)
        r = invoke(None, r_syms or {}, vector, timeout)
        return compare_call(vector, c, r, known)

    # --- real FFI against libc: marshalling + match ---
    v_abs = {"name": "abs", "function": "abs", "returns": "int",
             "args": [{"type": "int", "value": -5}]}
    check("scalar in/out matches → MATCH", verdict(v_abs)["verdict"] == "MATCH")
    check("real ctypes call actually ran (abs(-5)==5)",
          invoke(None, {}, v_abs, 3)["ret"] == 5)

    v_len = {"name": "strlen", "function": "strlen", "returns": "size_t",
             "args": [{"type": "cstr", "value": "hello"}]}
    check("string-arg function matches → MATCH", verdict(v_len)["verdict"] == "MATCH")
    check("strlen('hello')==5 via FFI", invoke(None, {}, v_len, 3)["ret"] == 5)

    v_cpy = {"name": "strcpy", "function": "strcpy", "returns": "ptr", "returns_ignore": True,
             "args": [{"type": "outbuf", "size": 8, "id": "dst"}, {"type": "cstr", "value": "abc"}]}
    check("output buffer compared, matches → MATCH", verdict(v_cpy)["verdict"] == "MATCH")
    check("strcpy wrote 'abc\\0' into the out buffer",
          invoke(None, {}, v_cpy, 3)["outputs"]["dst"][:4] == b"abc\x00")

    v_atof = {"name": "atof", "function": "atof", "returns": "double",
              "args": [{"type": "cstr", "value": "3.14"}]}
    check("double return (bit-compared) matches → MATCH", verdict(v_atof)["verdict"] == "MATCH")

    # --- a genuine return-value divergence via the symbol map ---
    v_case = {"name": "caseconv", "function": "caseconv", "returns": "int",
              "args": [{"type": "int", "value": 97}]}  # 'a'
    cs, rs = {"caseconv": "toupper"}, {"caseconv": "tolower"}
    res = verdict(v_case, cs, rs)
    check("divergent implementations (toupper vs tolower) → DIVERGE",
          res["verdict"] == "DIVERGE" and "return" in (res["diff"] or ""))

    # --- a pointer return that conveys POSITION must be compared by offset, not
    # collapsed to opaque "PTR" (strchr vs strrchr find 'l' at different offsets) ---
    v_find = {"name": "find", "function": "find", "returns": "ptr",
              "args": [{"type": "cstr", "value": "hello", "id": "s"}, {"type": "int", "value": 108}]}
    check("a ptr into a tracked buffer normalizes to its offset, not opaque PTR",
          invoke(None, {"find": "strchr"}, v_find, 3)["ret"] == ["offset", "s", 2])
    check("position-returning ptr: strchr vs strrchr differ by offset → DIVERGE",
          verdict(v_find, {"find": "strchr"}, {"find": "strrchr"})["verdict"] == "DIVERGE")
    check("position-returning ptr: same function agrees on the offset → MATCH",
          verdict(v_find, {"find": "strchr"}, {"find": "strchr"})["verdict"] == "MATCH")

    # --- ledger suppression + fingerprint pin (reused from diff_run) ---
    with tempfile.TemporaryDirectory() as d:
        led = os.path.join(d, "DIVERGENCES.md")
        open(led, "w").write("- [x] caseconv: intentional case-fold difference\n")
        res = verdict(v_case, cs, rs, ledger=led)
        check("ledgered divergence → DIVERGE(ledgered)", res["verdict"] == "DIVERGE(ledgered)")
        check("unpinned entry is flagged so it gets pinned",
              res["pinned"] is False and res["fingerprint"])
        fp = res["fingerprint"]
        open(led, "w").write(f"- [x] caseconv [sha256:{fp}]: case-fold difference\n")
        check("pinned fingerprint matches → suppressed",
              verdict(v_case, cs, rs, ledger=led)["verdict"] == "DIVERGE(ledgered)")
        open(led, "w").write("- [x] caseconv [sha256:000000000000]: stale\n")
        check("stale pin → DIVERGE again (a changed divergence re-fails)",
              verdict(v_case, cs, rs, ledger=led)["verdict"] == "DIVERGE")
        # LEDGER-STALE (LESSONS #14): a ledgered vector that now MATCHes must fail,
        # not silently pass — strlen matches on both sides, so a ledger entry for
        # it asserts a divergence that isn't there (fix reverted at library level).
        open(led, "w").write("- [x] strlen: pretend strlen diverges intentionally\n")
        check("a ledgered vector that now MATCHes → LEDGER-STALE",
              verdict(v_len, ledger=led)["verdict"] == "LEDGER-STALE")

    # --- crash isolation (fail-closed): a faulting C-ABI call is a finding ---
    v_boom = {"name": "boom", "function": "boom", "returns": "int",
              "args": [{"type": "int", "value": 3}]}
    check("rust-side crash → CRASH (never MATCH)",
          verdict(v_boom, {"boom": "abs"}, {"boom": "abort"})["verdict"] == "CRASH")
    with tempfile.TemporaryDirectory() as d:
        led = os.path.join(d, "DIVERGENCES.md")
        open(led, "w").write("- [x] boom: pretend this is fine\n")
        check("ledger cannot excuse a rust-side crash",
              verdict(v_boom, {"boom": "abs"}, {"boom": "abort"}, ledger=led)["verdict"] == "CRASH")
    check("C-only crash, rust returns cleanly → DIVERGE (ledgerable fix-of-C-defect)",
          verdict(v_boom, {"boom": "abort"}, {"boom": "abs"})["verdict"] == "DIVERGE")

    # --- timeout (liveness backstop): a rust-side hang is TIMEOUT, not MATCH,
    # and the reaper escalates to SIGKILL so a signal-ignoring child can't wedge us ---
    v_slow = {"name": "slow", "function": "slow", "returns": "int",
              "args": [{"type": "int", "value": 800000}]}  # usleep µs
    check("rust-side hang → TIMEOUT",
          verdict(v_slow, {"slow": "abs"}, {"slow": "usleep"}, timeout=0.3)["verdict"] == "TIMEOUT")

    # --- the exact 'return AND output state' rule (verdict logic, no FFI) ---
    def synth(status="ok", ret=0, outputs=None):
        return {"status": status, "ret": ret, "outputs": outputs or {}, "detail": ""}
    vs = {"name": "syn", "function": "f", "returns": "int", "args": []}
    check("same return, different output buffer → DIVERGE (output state is compared)",
          (r := compare_call(vs, synth(ret=1, outputs={"b": b"x"}),
                             synth(ret=1, outputs={"b": b"y"}), {}))["verdict"] == "DIVERGE"
          and "outbuf" in r["diff"])
    check("different return, same output → DIVERGE (return is compared)",
          compare_call(vs, synth(ret=1, outputs={"b": b"x"}),
                       synth(ret=2, outputs={"b": b"x"}), {})["verdict"] == "DIVERGE")
    check("same return and output → MATCH",
          compare_call(vs, synth(ret=1, outputs={"b": b"x"}),
                       synth(ret=1, outputs={"b": b"x"}), {})["verdict"] == "MATCH")
    # returns_ignore is load-bearing: a DIFFERING return is skipped (output decides)
    v_ig = {"name": "syn2", "function": "f", "returns": "ptr", "returns_ignore": True, "args": []}
    check("returns_ignore skips a DIFFERING return (output matches) → MATCH",
          compare_call(v_ig, synth(ret=1, outputs={"b": b"x"}),
                       synth(ret=2, outputs={"b": b"x"}), {})["verdict"] == "MATCH")
    check("without returns_ignore the same differing return → DIVERGE (flag is load-bearing)",
          compare_call(vs, synth(ret=1, outputs={"b": b"x"}),
                       synth(ret=2, outputs={"b": b"x"}), {})["verdict"] == "DIVERGE")

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
