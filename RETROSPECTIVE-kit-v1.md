# RETROSPECTIVE — the kit builds itself to v1.0

> **Status note — 2026-07-25.** This document is a **point-in-time record** of the
> v1.0 project; its body is deliberately left as written. Two of its statements have
> since been superseded, recorded here rather than edited into the text (a
> retrospective that quietly updates itself stops being evidence):
>
> * **Gate count.** The body says `check-kit` runs **14 gates**; it runs **24 as of
>   2026-07-25**, and will keep growing. Prose counts drift and no gate watches
>   prose — `make check-kit` is the only authority for the current number, so prefer
>   running it over quoting any figure here (LESSONS #15).
> * **CI.** §5 item 3 says Actions is policy-blocked here and neither workflow has
>   ever executed. **No longer true:** Actions runs in this repo now, and
>   `check-kit` + the skeleton workspace + the adler32 exit test have all gone green
>   in CI. The residual gap is narrower — the **sanitizers** and the **`porting-ci`
>   template** are still unexercised (LESSONS #15).
>
> * **The §5 plan is done.** Item 1 (port real foreign CVE-bearing C) landed as
>   the cJSON port — see `RETROSPECTIVE-cjson.md`; item 2 (gate-mutation
>   verification) exists as `harnesses/gate-mutation/`; item 3's CI half runs and
>   its sanitizer half now runs miri against that port.
>
> **Where to read next:** `RETROSPECTIVE-kit-audit.md` is the current-state
> document — the six-lens audit that followed, its findings, and the live v1.x
> backlog with burn-down status. `CODE-REVIEW.md` is the frozen full review of the
> pre-v1.0 snapshot (`9aa5984`) that produced LESSONS 006–008; it is history, kept
> as the evidence behind those lessons, and is not maintained against the current
> tree.

Project-wide retrospective (per `PROMPTS/90-retrospective.md`) covering the
`c2rust-port` repo from the lift snapshot (`9aa5984`, 2026-07-19) to the `v1.0`
tag (`e1246bd`, 2026-07-20) and the post-tag hardening on top of it. The
"port" under retrospective here is the **kit itself**: three days in which it was
reviewed, repaired, extended to its full backlog, proven on a real C→Rust
library port, and made to learn eight new lessons — using its own process the
whole way. Companion to `RETROSPECTIVE-lsof.md` (the port that created the kit);
this is the retrospective of the kit becoming a product.

Step 0 was executed, not narrated: `make check-kit` green (14 gates: every
harness self-test + doc-flag drift + skills integrity + the toolchain-optional
skeleton gate), and the `examples/adler32` exit test run end-to-end on real
binaries — including a deliberate fail-closed probe (ledger emptied → the run
aborts, no success banner). That probe found real defects; see §4.

## 1. The arc, reconstructed from artifacts

Nine PRs; five merged, four superseded. Two work streams, one collision.

| PR | What | Outcome |
|---|---|---|
| #1 | Full code review of the snapshot: **26 findings** (6 High — all fail-open gates; 8 Medium; 12 Low), every one fixed with a pinned test, + LESSONS 006–008 | merged |
| #2 | Differential fuzzing (`diff-fuzz`), built on a `compare_one` extraction so fidelity is shared, not copied | merged |
| #3 | P0 harnesses: `cando` driver differential + `perf` gate; the hermetic-stdin (`DEVNULL`) fix; the kit-repo CI workflow; skeleton made to pass its own lints | merged |
| #4 | Retrospective of that round: LESSONS 009–011, the skeleton gate, the CI-policy caveat | merged |
| #5–#8 | A **parallel session's** stacked stream: golden holdout/validate, `lib_diff` (ctypes library differential), its own perf gate, scanner depth, CI-template hardening, precondition skill, normalize rules-as-data, progress ingest, the adler32 exit test | closed, superseded |
| #9 | The reconcile: replays #5–#8 onto the moved `main`, with explicit keep/drop decisions (keep main's `cando`+`perf`, land `lib_diff` as a complement, drop the duplicate `perf-gate/`) | merged → `v1.0` |

By the numbers: **LESSONS 001–011 → 013** (this doc adds two); the §5 backlog
burned down completely (11/11); harness count 8 → **15**; skills 6 → 8;
`check-kit` grew from 11 checks to 14 gates; and the exit test drives a real
buggy-C library through every gate with the C's overflow caught by *both*
library differentials and pinned in the ledger.

## 2. What demonstrably worked

- **The compounding loop is real, not aspirational.** Every retrospective pass
  produced lessons that were *mechanized the same day* (fail-closed timeouts,
  the doc-flag gate, ledger pins, the skeleton gate) — and later work was caught
  by gates earlier work installed. `check-kit` caught drift repeatedly during
  development; that is the loop paying for itself inside one project.
- **Execution beats reading, every single time.** All 26 review findings were
  confirmed by running proof-of-concept experiments; every retrospective's
  biggest finding came from step 0 (running the tools), never from prose review.
  This project adds two more instances (§4). The kit's oldest meta-lesson
  ("a dry-run that doesn't run the tools is theater") is now 5-for-5.
- **Shared fidelity as architecture.** Extracting `compare_one` meant the
  matrix differential, the fuzzer, and the driver-based library differential
  share one verdict: stdout+exit, fail-closed timeouts, fingerprinted ledger.
  Lessons live in exactly one place; a fix there upgrades four gates at once.
- **Adversarial process on the kit's own code.** The parallel stream's
  adversarial-review passes (golden hardening, `lib_diff` crash isolation) and
  this stream's degenerate-case probes both found real fail-open defects before
  they shipped. Skepticism against one's own harnesses is the kit's most
  productive habit.

## 3. Failure inventory (what it cost)

1. **The snapshot's gates failed open** (6 High findings): both-hang → MATCH,
   hang enshrined as golden, stdout-only golden, `*`-line skip, vacuous fuzz
   job, never-runnable sanitizer job. Root cause: self-tests proved *detection*,
   never *refusal*. → LESSONS #6 and the "gates fail closed" rule.
2. **Docs drifted from tools** (phantom flags/categories, paste-broken orders,
   a smoke-test command that failed in the kit's own repo). → LESSONS #7 + the
   `doc-check` gate.
3. **Two streams built the same P0 twice.** PR #3 and PR #5, from different
   sessions, independently implemented the library differential and the perf
   gate. Cost: a dedicated reconcile PR, four superseded PRs, keep/drop
   adjudication, and `git cherry` false alarms afterward (re-committed work has
   new patch-ids, so "merged?" became a manual forensic question). Upside,
   honestly: the two library differentials were *different by design* (driver
   subprocess vs ctypes) and were kept as complements — accidental duplication
   converted into deliberate diversity. → LESSONS #12.
4. **Recorded lessons recurred in new code.** The exit test — written *after*
   LESSONS #6 and #8 were logged — shipped fail-open (`set -uo` without `-e`; a
   `| grep … || true` that swallowed `cargo test` failures) and with name-only
   unpinned ledger entries. Both were caught only because this retrospective's
   step 0 *ran* the tools (the harness printed its own pin warning; the `-e`
   probe proved the abort). A lesson in the log is not a control. → LESSONS #13,
   and the exit test is now fail-closed, pinned, and wired into the CI workflow
   so it cannot rot silently.
5. **Environment assumptions burned real time**: the Actions-policy
   `startup_failure` saga (LESSONS #10), the inherited-stdin hang (#11), the
   skeleton failing its own lints (#9). Common thread: the kit had only ever
   run in the environment that built it.

## 4. This retrospective's own step-0 findings (fixed in this change)

- The exit test **failed open** (LESSONS #6 recurrence): any gate failure still
  printed the success banner and exited 0. Now `set -euo pipefail` with the
  `cargo test` output captured-then-checked; probed by emptying the ledger →
  `[DIVERGE] overflow`, exit 1, no banner.
- The exit test's ledger entries were **unpinned** (LESSONS #8 recurrence),
  and `lib_diff` had been printing the pin hint on every run. Now pinned to
  their fingerprints, with a comment explaining why a pin re-failing on a
  harness-format change is the pin working.
- The exit test ran **nowhere automatically** (needs cc+cargo, so it can't be
  in the toolchain-free `check-kit`). Now a third job in
  `.github/workflows/check-kit.yml`, active as soon as Actions is enabled.

## 5. The plan (v1.x)

v1.0 is tagged; the §5 backlog is empty. What remains is *proof under load* and
the residual risks this project could not discharge from inside its own repo —
in priority order:

1. **Port a real, mid-size C codebase with the kit.** The compounding loop's
   delivery mechanism is a port; the kit has now only reviewed itself and driven
   a toy. Pick a parser-heavy, CVE-bearing C library (the kit's sweet spot:
   untrusted input, real flaw inventory), run kickoff → precondition → oracle
   (holdout + validate) → module loop → audit → retrospective, and let LESSONS
   014+ come from *foreign* code. Every item below can ride along with it.
2. **Gate-mutation verification** ("break a gate, prove the suite goes red") —
   the standing "failure the kit still would not prevent" since retro #1, now
   sharpened by LESSONS #13: fail-closed coverage is only as good as the
   fixtures someone remembered. A small harness that flips one gate's verdict
   logic (or blanks its input) and asserts `check-kit`/CI fails would make the
   gate set self-verifying.
3. **Run the CI for real.** Neither the kit's own workflow nor the hardened
   `porting-ci` template has ever executed — Actions is policy-blocked in this
   repo (LESSONS #10). Enable Actions here (or mirror to a repo where it runs),
   watch `check-kit` + skeleton + exit-test go green in CI, and exercise the
   template in the real port from item 1. Until then "CI-hardened" is a claim,
   not an observation.
4. **Hazardous-API pattern library** — LESSONS #1's residual: the kit can make
   a hang visible early but cannot supply the avoid-the-call design insight.
   Start the catalogue from the winlsof recipes (type-index pre-probe, etc.)
   and grow it one real port at a time.
- **Standing discipline** (no new machinery): one stream on the trunk at a time
  or explicit file-ownership partitions (LESSONS #12); every new kit artifact
  reviewed against the LESSONS list before merge (#13, now in PROMPTS/90); the
  retrospective after every port — the rule that produced all of this.

## 6. The verdict

The kit entered this project as a promising snapshot whose safety gates could
pass while checking nothing. It leaves as a self-verifying toolchain: 15
harnesses that fail closed, a mechanical drift gate over its own docs and
skills, a template that passes its own lints, a real port driven through every
gate, and thirteen mechanized lessons. The next lesson should be bought where
the kit was always meant to spend: someone else's C.
