---
name: porting-kit-oracle
description: Establish the differential oracle and test-vector harness BEFORE translating any C to Rust. Use in Phase 2, or whenever the user needs to lock the reference behavior / build the input matrix / set up golden tests for a C-to-Rust port. Enforces "semantic equivalence, not it-builds" — the single biggest finding behind translation failures.
---

# Porting Kit — establish the oracle (test harness first)

Wraps the differential + golden harnesses and PLAYBOOK Phase 2 / synthesis Step 0.5.
**Do this before writing Rust.** TRACTOR's central finding: most failures are at the
semantic-comparison stage, not build time — "it builds" tells you almost nothing.

## Procedure
1. **Lock the C binary** at a known commit as the reference oracle.
2. **Build the input matrix** from `porting-kit/harnesses/differential/input-matrix.example.toml`.
   Cover: every output format, every flag, empty/edge inputs, large inputs, and —
   critically — malformed/hostile inputs and **every integer boundary**
   (`INT_MAX`/`CHAR_MAX`, off-by-one indices, empty buffers): the UB shapes a rewrite
   must handle better than C.
3. **Capture + version the golden corpus**, flagging oracle nondeterminism so you
   normalize it instead of enshrining it:
   `python3 porting-kit/harnesses/golden/golden.py capture --oracle <c-bin> --matrix <m> --corpus <dir>`
4. **Tune normalization** (`porting-kit/harnesses/differential/normalize.py`) so
   PIDs/timestamps/pointers/ephemeral-ports are masked *identically* on both sides —
   whatever you erase from C you must erase from Rust, or you manufacture a divergence.
   Put project-specific masks in a rules file — `normalize.py --rules <file>` (start
   from `normalize.py --dump-default-rules`), also accepted by `diff_run.py --rules`.
5. **Validate every vector against the C first** — a wrong vector that "passes"
   teaches nothing — and **hold back a hidden acceptance set** (an LLM overfits the
   vectors it can see): `golden.py capture --oracle <c> --matrix <m> --corpus <dir>
   --holdout <heldback> --validate`. `--validate` refuses any vector that fails on C;
   `--holdout` reserves the hidden set that `golden.py replay ... --final` runs only
   at acceptance (an iteration `replay` refuses a leaked held-out vector).
6. **Seed `DIVERGENCES.md`** (copy `porting-kit/skeleton/DIVERGENCES.md`) from the
   Phase-0 flaw scan — the intentional-divergence ledger the differential reads.
7. **Wire the differential** (used per module in `porting-kit-module`):
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust <rust> --matrix <m> --ledger DIVERGENCES.md`
   The verdict is stdout **and** exit code; a per-case timeout is the liveness
   backstop (a hang isn't UB, so sanitizers miss it).
8. **For a C-ABI library** (no CLI), use the function-level differential instead of
   (or alongside) the executable one: fill `porting-kit/harnesses/cando/driver.template.c`
   and `driver.template.rs` (thin dispatch: argv → one library call → canonical
   stdout), build one against C and one against Rust, write a
   `porting-kit/harnesses/cando/vectors.example.toml` suite, then
   `python3 porting-kit/harnesses/cando/cando_diff.py --oracle-driver <c> --rust-driver <rust> --vectors <suite> --ledger DIVERGENCES.md`.
   It diffs per function and **baseline-validates**: a vector the C driver rejects is
   a BADVECTOR, not a Rust verdict ("a vector must pass on C before it may judge Rust").
   A no-driver alternative for simple C-ABI signatures is
   `porting-kit/harnesses/library-differential/lib_diff.py` (ctypes; compares the
   return value + mutated output buffers directly, crash/timeout-isolated per call).
9. **Add the performance gate** once both build:
   `python3 porting-kit/harnesses/perf/perf_gate.py --oracle <c> --rust <rust> --matrix <m>`
   (fails a case >1.3x the C median; run it per module in `porting-kit-audit`).

## Integrity
Harness paths/subcommands/flags must match the kit. If they drift, fix the reference
and re-run the kit's `make check-kit` (`make -C porting-kit check-kit` when vendored).
