#!/usr/bin/env python3
"""Function-level differential — the `cando`-style harness for C-ABI LIBRARIES.

The executable differential (diff_run.py) drives a whole program (argv/stdin →
stdout/exit). A *library* has no CLI: its behavior lives in individual exported
functions. This harness tests those functions by driving two thin driver
executables — one built against the C library, one against the Rust port — over a
vector suite of function calls, and diffing the results. (Named for lsof's
`cando()`; PLAYBOOK Phase 2 / synthesis Step 0.5: "for a C-ABI library, use a
cando-style function-level harness.")

Driver protocol (see driver.template.c / driver.template.rs):
    driver <func> [arg ...]     # optional stdin
  prints the function's result CANONICALLY to stdout (byte-identical format on
  both sides), exit 0 on success, nonzero on error/unsupported.

Vector suite (TOML or JSON): a list of calls —
    [[call]]
    func = "parse_header"
    args = ["\\x01\\x02", "16"]
    # optional: name, stdin, env, timeout

Two properties, both enforced:
  * DIFFERENTIAL — the Rust result must match the C result (stdout AND exit code,
    via diff_run.compare_one, so the fidelity/timeout/ledger rules are shared, not
    reimplemented). Intentional fix-of-C-defect divergences are ledgered.
  * C-BASELINE VALIDATION — a vector the C driver itself rejects (nonzero exit /
    timeout) is a BAD VECTOR, reported and NOT counted as a Rust pass or fail: "a
    vector must pass on C before it may judge Rust" (OPERATING-GUIDE §5 P0). Opt
    out per-suite with --allow-oracle-error when a nonzero status is a valid result.

Usage:
  cando_diff.py --oracle-driver PATH --rust-driver PATH --vectors FILE
                [--ledger DIVERGENCES.md] [--allow-oracle-error] [--json]
  cando_diff.py --self-test
Exit: 0 = all match (or ledgered) and every vector baseline-valid; 1 = a
divergence, a timeout, or a bad vector; 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "differential"))
import diff_run as D          # noqa: E402  (compare_one / load_ledger / TOML+JSON loader)


def load_vectors(path):
    """Load a `[[call]]` vector suite (TOML or JSON). Same shape as a diff_run
    matrix but keyed `call`, and each entry names a `func`."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        calls = data["call"] if isinstance(data, dict) and "call" in data else data
    else:
        try:
            import tomllib
        except ModuleNotFoundError:
            sys.exit("error: TOML vectors need Python 3.11+ (tomllib); use a .json suite instead")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        calls = data.get("call", data if isinstance(data, list) else [])
    for i, c in enumerate(calls):
        if not c.get("func") or not isinstance(c["func"], str):
            sys.exit(f"error: vector #{i} needs a string `func`")
    return calls


def _case_for(call, index):
    """Map a function-call vector to a diff_run case: argv = [func] + args."""
    func = call["func"]
    name = call.get("name") or f"{func}#{index}"
    args = [func] + [str(a) for a in call.get("args", [])]
    case = {"name": name, "args": args}
    for k in ("stdin", "env", "timeout"):
        if k in call:
            case[k] = call[k]
    return case


def compare(oracle_driver, rust_driver, vectors, ledger, allow_oracle_error):
    known = D.load_ledger(ledger)
    results = []
    for i, call in enumerate(vectors):
        case = _case_for(call, i)
        r = D.compare_one(case["name"], oracle_driver, rust_driver, case, known,
                          sort=False, mask_numbers=False)
        # C-baseline validation: if the C driver rejected the vector (nonzero
        # exit or timeout), it can't validate the Rust — it's a bad vector, not
        # a Rust verdict. `--allow-oracle-error` opts out (nonzero is a result).
        oracle_errored = r["oracle_rc"] != 0 or r["timed_out"]["oracle"]
        if oracle_errored and not allow_oracle_error:
            results.append({"name": case["name"], "func": call["func"],
                            "verdict": "BADVECTOR", "oracle_rc": r["oracle_rc"],
                            "diff": f"oracle driver rejected the vector "
                                    f"(rc={r['oracle_rc']}, timeout={r['timed_out']['oracle']}); "
                                    f"a vector must pass on C before it can judge Rust\n"})
        else:
            results.append({"name": case["name"], "func": call["func"],
                            "verdict": r["verdict"], "oracle_rc": r["oracle_rc"],
                            "fingerprint": r["fingerprint"], "pinned": r["pinned"],
                            "diff": r["diff"]})
    return results


def run(oracle_driver, rust_driver, vectors_path, ledger, allow_oracle_error, as_json):
    results = compare(oracle_driver, rust_driver, load_vectors(vectors_path),
                      ledger, allow_oracle_error)
    bad = [r for r in results if r["verdict"] in ("DIVERGE", "TIMEOUT", "BADVECTOR")]
    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"[{r['verdict']:18}] {r['name']}")
            if r["verdict"] in ("DIVERGE", "TIMEOUT", "BADVECTOR") and r.get("diff"):
                sys.stdout.write(r["diff"])
        n_bad = sum(1 for r in results if r["verdict"] == "BADVECTOR")
        n_div = sum(1 for r in results if r["verdict"] in ("DIVERGE", "TIMEOUT"))
        print(f"\n{len(results)} vector(s): {n_div} divergence(s), {n_bad} bad vector(s)")
        if n_bad:
            print("BADVECTOR: the C driver rejected these — fix the vector (or "
                  "--allow-oracle-error if a nonzero status is a valid result).")
        if n_div:
            print("Triage each divergence: fix the Rust, OR ledger the intentional "
                  "fix-of-C-defect (`- [x] <name> [sha256:..]: why`).")
    return 1 if bad else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    # Two function-level drivers. Both implement add/neg; the "rust" one diverges
    # on neg(0) (prints "-0" where C prints "0"). add() rejects non-int args with
    # a nonzero exit on the C side → that vector is a BAD VECTOR.
    oracle_src = (
        "#!/usr/bin/env python3\nimport sys\n"
        "f=sys.argv[1]; a=sys.argv[2:]\n"
        "if f=='add':\n"
        "    try: print(int(a[0])+int(a[1]))\n"
        "    except Exception: sys.exit(3)\n"
        "elif f=='neg': print(-int(a[0]))\n"
        "else: sys.exit(4)\n")
    rust_src = (
        "#!/usr/bin/env python3\nimport sys\n"
        "f=sys.argv[1]; a=sys.argv[2:]\n"
        "if f=='add':\n"
        "    try: print(int(a[0])+int(a[1]))\n"
        "    except Exception: sys.exit(3)\n"
        "elif f=='neg': print('-%d' % int(a[0]))\n"   # diverges on neg 0 → "-0"
        "else: sys.exit(4)\n")

    with tempfile.TemporaryDirectory() as d:
        oracle = os.path.join(d, "oracle_driver.py"); open(oracle, "w").write(oracle_src); os.chmod(oracle, 0o755)
        rust = os.path.join(d, "rust_driver.py"); open(rust, "w").write(rust_src); os.chmod(rust, 0o755)
        vectors = [
            {"func": "add", "args": [2, 3]},      # MATCH
            {"func": "neg", "args": [5]},          # MATCH
            {"func": "neg", "args": [0]},          # DIVERGE ("-0" vs "0")
            {"func": "add", "args": ["x", 1]},     # BADVECTOR (oracle exits 3)
        ]
        res = compare(oracle, rust, vectors, ledger=None, allow_oracle_error=False)
        by = {r["name"]: r["verdict"] for r in res}
        check("matching function calls → MATCH",
              by["add#0"] == "MATCH" and by["neg#1"] == "MATCH")
        check("a per-function divergence is caught", by["neg#2"] == "DIVERGE")
        check("a vector the C driver rejects is a BADVECTOR (baseline validation)",
              by["add#3"] == "BADVECTOR")

        # --allow-oracle-error turns the rejected vector into an ordinary compare
        # (both sides exit 3 identically → MATCH), not a bad vector.
        res = compare(oracle, rust, [{"func": "add", "args": ["x", 1]}],
                      ledger=None, allow_oracle_error=True)
        check("--allow-oracle-error: nonzero status compared, not rejected",
              res[0]["verdict"] == "MATCH")

        # a ledger pin suppresses the intentional divergence (shared with diff_run)
        r_div = [r for r in compare(oracle, rust, [{"func": "neg", "args": [0]}],
                                    ledger=None, allow_oracle_error=False)][0]
        led = os.path.join(d, "DIVERGENCES.md")
        open(led, "w").write(f"- [x] neg#0 [sha256:{r_div['fingerprint']}]: Rust prints signed zero; intentional\n")
        res = compare(oracle, rust, [{"func": "neg", "args": [0]}],
                      ledger=led, allow_oracle_error=False)
        check("ledgered function divergence → suppressed",
              res[0]["verdict"] == "DIVERGE(ledgered)")

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle-driver", help="driver built against the C library")
    ap.add_argument("--rust-driver", help="driver built against the Rust port")
    ap.add_argument("--vectors", help="function-call vector suite (.toml or .json)")
    ap.add_argument("--ledger", default="DIVERGENCES.md", help="known-intentional-divergence ledger")
    ap.add_argument("--allow-oracle-error", action="store_true",
                    help="treat a nonzero oracle exit as a valid result, not a bad vector")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.oracle_driver and args.rust_driver and args.vectors):
        ap.print_usage(sys.stderr)
        print("error: --oracle-driver, --rust-driver and --vectors are required (or --self-test)",
              file=sys.stderr)
        return 2
    return run(args.oracle_driver, args.rust_driver, args.vectors,
               args.ledger, args.allow_oracle_error, args.json)


if __name__ == "__main__":
    sys.exit(main())
