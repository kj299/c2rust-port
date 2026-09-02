---
name: porting-kit-audit
description: Run the full safety-gate suite against a Rust port and report a gate-status table. Use before a merge or release, or whenever the user asks "is this port safe / secure / ready", to verify unsafe is contained + documented, no UB, no panic on input, clean supply chain, and no silent behavior drift.
---

# Porting Kit — safety-gate audit

Runs every control in `porting-kit/SECURITY-CHECKLIST.md` and reports pass/fail.
Nothing here is optional for a "safe" verdict; a module that compiles and matches the
oracle is at gate 2 of 6, not done.

## Procedure — run each gate, collect results

0. **Every declared control actually RUNS** (do this first — it decides whether
   the rest of this list is even being executed):
   `python3 porting-kit/harnesses/control-coverage/check_controls.py --controls
   porting-kit/CLAUDE.md --gate <port>/check.sh` → must be 0 unwired.
   At the cJSON cutover three of six controls below — supply-chain, c-flaw-scan
   and threat-model, two of them "hard fail" — were in this list and in the
   mutation sweep, yet the port's gate script never called any of them
   (LESSONS #31). Reading a gate script cannot show you an absence; ask the tool.
   Then: `python3 porting-kit/harnesses/api-coverage/check_api.py --header <c.h>
   [--header <c2.h> ...] --manifest API-COVERAGE.md` → every exported symbol
   `ported`, or `unported`/`out-of-scope` with a written reason and within the
   ceiling the manifest declares. cJSON module 9 passed six gates, a 25k fuzz
   sweep and a retrospective with 2 of 14 public symbols unported, because
   LESSONS #26 said to check this in prose and nothing enforced it (LESSONS #34).
   **Pass EVERY public header in one invocation** and check the report's scope
   against the library's headers yourself: pointed at one header the gate is
   green over that header alone, which is how cJSON kept 35 ungated base-library
   entry points under a green api-coverage line (LESSONS #35). A green run that
   prints an UNPORTED count is not a complete API — quote that count in the
   audit report rather than writing "api-coverage: PASS".
1. **Unsafe contained + documented** (toolchain-free hard gate):
   `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py crates/`  → must be 0
   undocumented. (On a real backend this found 51/131 undocumented — exactly what a
   gate catches.) Plus `cargo clippy --all-targets -- -D warnings -D
   clippy::missing_safety_doc -D clippy::undocumented_unsafe_blocks`.
2. **No UB:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh all .`
   (Miri + ASan/UBSan; TSan for threaded code — the class that hides the hang bugs.)
3. **No panic on input:** `cargo fuzz list` then a 60s smoke per target. Any crash blocks.
4. **Clean supply chain:** `bash porting-kit/harnesses/supply-chain/run_supply_chain.sh .`
   (`cargo audit` + `cargo deny`: no advisories, licenses allow-listed, crates.io-only.)
5. **No silent drift:** the differential shows MATCH or a ledgered divergence
   (`diff_run.py ... --ledger DIVERGENCES.md`).
6. **Least privilege / no secrets / signed build / current threat model** — walk the
   per-release section of `SECURITY-CHECKLIST.md`.
7. **Performance sanity:**
   `python3 porting-kit/harnesses/perf/perf_gate.py --oracle <c> --rust <rust> --matrix <m>`
   fails a module >1.3x the C median runtime (`--threshold` to tune) — a specific bug
   (a copy, a missed release build, bounds checks in a hot loop), not "the cost of Rust".
   A spawn-dominated case is reported UNMEASURABLE (give it a real workload), never a
   false pass.
8. **CI hygiene** (LESSONS #5): confirm each language/subtree's CI is path-scoped so
   unrelated changes don't trigger heavyweight jobs or leave PRs misleadingly
   "unstable"; see `porting-kit/harnesses/ci/porting-ci.template.yml`.

## Report
Emit a gate-status table via `python3 porting-kit/harnesses/progress/progress.py show`
and call out any red gate with the exact command to reproduce it. Do not report "safe"
unless every applicable gate is green (or a divergence is ledgered with justification).

## Integrity
Gate commands must match the harnesses and SECURITY-CHECKLIST. Fix the reference on
drift; re-run the kit's `make check-kit` (`make -C porting-kit check-kit` when vendored).
