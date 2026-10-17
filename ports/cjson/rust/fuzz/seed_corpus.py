#!/usr/bin/env python3
"""Seed the cargo-fuzz corpora from the port's differential matrices.

    seed_corpus.py ORACLE_DIR FUZZ_DIR

Writes FUZZ_DIR/corpus/parse_print/ (every case's stdin bytes) and
FUZZ_DIR/corpus/modes/ (each case as `[mode index] + stdin`, the framing
fuzz_targets/modes.rs reads). The corpora are regenerated on every run and
gitignored; the matrices are the committed truth.

The mode order is READ from fuzz_targets/modes.rs, never restated here: a
second copy of that list would have to be edited in lockstep with the first,
which is the LESSONS #25 shape. And every mode a matrix case uses must be in
it — a mode the target cannot select is a surface the fuzzer never reaches, so
that fails here instead of silently dropping the seeds (LESSONS #26).
Exit: 0 = seeded; 1 = a matrix mode missing from MODES, or nothing seeded;
2 = unreadable input.
"""
import base64
import glob
import hashlib
import json
import os
import re
import sys


def modes_order(fuzz_dir):
    src = open(os.path.join(fuzz_dir, "fuzz_targets", "modes.rs"), encoding="utf-8").read()
    m = re.search(r"const MODES: &\[&str\] = &\[(.*?)\];", src, re.S)
    if not m:
        sys.exit("error: no `const MODES` list in fuzz_targets/modes.rs")
    return re.findall(r'"([^"]+)"', m.group(1))


def case_bytes(case):
    if "stdin_b64" in case:
        return base64.b64decode(case["stdin_b64"])
    return case.get("stdin", "").encode("utf-8")


def write(dirpath, data):
    name = hashlib.sha1(data).hexdigest()
    with open(os.path.join(dirpath, name), "wb") as fh:
        fh.write(data)


def main():
    if len(sys.argv) != 3:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    oracle_dir, fuzz_dir = sys.argv[1], sys.argv[2]
    order = modes_order(fuzz_dir)
    index = {m: i for i, m in enumerate(order)}
    pp = os.path.join(fuzz_dir, "corpus", "parse_print")
    md = os.path.join(fuzz_dir, "corpus", "modes")
    os.makedirs(pp, exist_ok=True)
    os.makedirs(md, exist_ok=True)
    matrices = sorted(glob.glob(os.path.join(oracle_dir, "matrix*.json")))
    if not matrices:
        print(f"error: no matrix*.json under {oracle_dir}", file=sys.stderr)
        return 2
    missing, n = set(), 0
    for path in matrices:
        data = json.load(open(path, encoding="utf-8"))
        for case in data if isinstance(data, list) else data.get("case", []):
            mode = (case.get("args") or [""])[0]
            stdin = case_bytes(case)
            write(pp, stdin)
            if mode not in index:
                missing.add(mode)
                continue
            write(md, bytes([index[mode]]) + stdin)
            n += 1
    if missing:
        print(f"error: matrix modes the `modes` fuzz target cannot select: "
              f"{sorted(missing)} — add them to MODES in fuzz_targets/modes.rs",
              file=sys.stderr)
        return 1
    if n == 0:
        print("error: no seeds written", file=sys.stderr)
        return 1
    print(f"seeded {n} case(s) from {len(matrices)} matrices")
    return 0


if __name__ == "__main__":
    sys.exit(main())
