# LESSONS — append-only log

Every port appends here (via `PROMPTS/90-retrospective.md`). This is how the kit
compounds: each entry names a lesson, the codebase that taught it, and the
`PLAYBOOK.md`/harness section it amended. **Append only — never rewrite history.**

Format per entry:

    ## NNN. <one-line lesson>
    - **Date:** YYYY-MM-DD
    - **Codebase:** <project> (<language/domain>)
    - **What happened:** <the failure or insight, grounded in evidence>
    - **Kit change:** <the concrete PLAYBOOK/harness/template edit made>
    - **Section amended:** <file · section>

---

## 001. The kit's own dry-run against lsof's failure inventory

- **Date:** 2026-07-05
- **Codebase:** winlsof (C `lsof` → Rust, Windows) — Phase 3 self-validation
- **What happened:** Walking `PLAYBOOK.md` end-to-end against the
  `RETROSPECTIVE-lsof.md` §6 failure inventory surfaced five failures the
  playbook, as first drafted, would *not* have prevented. Each was fixed in the
  playbook and is recorded below. This is entry #1 because the first thing the
  kit did was find its own gaps.

  1. **The hang wasn't spiked because it wasn't *recognized* as hazardous.**
     The "spike the scary module first" rule can only fire on a hazard someone
     wrote down. The 7-commit `NtQueryObject` hang had no such note.
     → **Kit change:** Phase 0 now requires *classifying the FFI/syscall surface
     by failure mode* (blocks-indefinitely? needs-privilege? version-variant?),
     which is what arms the spike-first rule.
     → *Section amended:* PLAYBOOK · Phase 0 "Do".

  2. **Hangs are invisible to the safety gates.** A deadlock/blocking call is a
     liveness bug, not UB — Miri/ASan/TSan don't flag it, and "compiles + matches
     oracle" hides it. The playbook's gate set had no liveness check.
     → **Kit change:** documented that the differential harness's per-case
     timeout (`diff_run.py` → `<<TIMEOUT>>`) IS the liveness backstop, and a
     timeout is a design smell to be *designed out*, not wrapped.
     → *Section amended:* PLAYBOOK · Phase 4 gate 2.

  3. **The research-grade spike-and-gate ritual — winlsof's biggest win — was
     underweighted.** The draft only spiked *hazardous modules*, not *capabilities
     that might be impossible*. Those need effort/confidence ratings, a written
     decision gate, and a pivot check (winlsof's ETW pivot: couldn't get the real
     FD, but shipped raw/ICMP/AF_UNIX coverage instead).
     → **Kit change:** added the explicit spike-and-gate sub-process.
     → *Section amended:* PLAYBOOK · Phase 4 (research-grade capability).

  4. **The test harness's host fought back and the playbook didn't warn of it.**
     Six commits went to PowerShell-5.1 / Windows-1252 breakage *in the harness*.
     → **Kit change:** Phase 2 now has a "harden the harness for its host" step
     (write kit harnesses in a portable language — Python + POSIX sh, done — and
     pin the tool's default output encoding to the target's default shell).
     → *Section amended:* PLAYBOOK · Phase 2 "Do".

  5. **Environment friction (toolchain / synced build dir) ate time with no code
     cause.** MSVC-vs-GNU linker mismatch; OneDrive locking `target\`.
     → **Kit change:** Phase 3 gained an "environment preflight" exit criterion.
     → *Section amended:* PLAYBOOK · Phase 3.

- **Validation the kit already pays off:** running the new
  `unsafe-audit/audit_unsafe.py` against the shipped winlsof backend reported
  **131 real `unsafe` blocks, 51 undocumented** — empirically confirming the
  retrospective's inferred "144-vs-91" gap (the tool correctly excludes the
  comment/string matches that inflated the raw grep). The hard-fail gate would
  have prevented every one of those 51 from merging undocumented.
- **Still not prevented (the next port's target):** the kit cannot force the
  *design insight* that ended the hang (avoid the blocking call via a type-index
  pre-probe). It can make the hang *visible* early (classification + timeout
  gate) and buy time to find the insight, but inventing the safe design remains
  human/agent work. A future kit lesson may add a "hazardous-API pattern library"
  of known avoid-the-call recipes.

---

## 002. A noisy Phase-0 scanner is worse than none — it gets ignored

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 1 (kit run against lsof's *actual* C tree)
- **What happened:** Running `c-flaw-scan/scan_c_flaws.py` against real lsof
  (`lib/ src/`) returned **1044 hits, of which 828 were false "format-string"
  positives.** The check flagged arg 0 of every printf-family call, but the
  format string is not arg 0 for `fprintf`/`sprintf`/`snprintf`/`syslog`/`err`
  (it follows the stream / buffer / size / priority). So every
  `fprintf(stderr, "literal", ...)` — the overwhelmingly common, *safe* case —
  was flagged. A Phase-0 tool that cries wolf 828 times gets muted, and the
  ~215 real candidates (97 TOCTOU, 94 integer-overflow, 24 unbounded-copy) drown
  in the noise. That is the exact opposite of the tool's purpose: to *bootstrap
  the flaw inventory*. This is itself a lsof-class failure — a control so noisy
  it is ignored is a broken control (the retrospective's own "a skipped control
  is a broken control").
- **Kit change:** rewrote the format-string check to locate the *format-position*
  argument per function (a small arg-list parser + per-function format index)
  and flag only when that argument is a **non-literal**. Result on the same lsof
  tree: format-string **828 → 8** (all 8 genuine non-literal formats), total
  **1044 → 224**. Pinned with a self-test that asserts `fprintf(stderr, var, ...)`
  flags but `fprintf(stderr, "literal", ...)` and `snprintf(buf, n, "%d", ...)`
  do not.
- **Section amended:** harnesses/c-flaw-scan/scan_c_flaws.py (`FORMAT_FUNCS`,
  `_call_args`, `_scan_format_strings`); the general principle — *tune every
  Phase-0 scanner for signal-to-noise against the real target before trusting
  it* — belongs to PLAYBOOK · Phase 0.

---

## 003. A "delegated" control that nothing enforces is not a control

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 2 (kit run against lsof/winlsof's real code)
- **What happened:** The unsafe-audit harness documents that it covers `unsafe {}`
  blocks + `unsafe impl`, and *delegates* `unsafe fn` `# Safety`-doc coverage to
  "clippy's `missing_safety_doc`." But grepping the shipped winlsof backend found
  **11 `unsafe fn` / `unsafe extern fn` definitions** (ETW callbacks and TDH
  property parsers — real FFI-facing unsafe surface), and **neither the CI
  template nor the skeleton enabled that clippy lint** (it is allow-by-default).
  So the delegation was fiction: no tool, anywhere, checked that any `unsafe fn`
  had a safety contract. A control you point at another tool that you never turn
  on is worse than an acknowledged gap — it reads as covered.
- **Kit change:** wired the clippy half for real. `[workspace.lints]` in the
  skeleton now sets `clippy::missing_safety_doc` + `undocumented_unsafe_blocks`
  (plus `cast_possible_truncation` and `arithmetic_side_effects` — the C-idiom
  footguns), each crate opts in via `[lints] workspace = true`, and the CI
  clippy step passes `-D clippy::missing_safety_doc -D
  clippy::undocumented_unsafe_blocks` as belt-and-suspenders for repos that copy
  the CI without the lints table. Documented the two-layer split (harness =
  toolchain-free block gate; clippy = `unsafe fn` docs + block cross-check) in
  the harness docstring and SECURITY-CHECKLIST. Skeleton still builds offline.
- **Section amended:** skeleton/Cargo.toml (`[workspace.lints]`) + each crate's
  `[lints]`; harnesses/ci/porting-ci.template.yml (clippy step);
  SECURITY-CHECKLIST · per-module; audit_unsafe.py docstring.

---

## 004. Differential fidelity is stdout AND exit code, not stdout alone

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 3 (kit run against lsof's real behavior)
- **What happened:** `diff_run.py` *captured* both binaries' exit codes but its
  verdict was computed from normalized stdout only — the codes were reported and
  ignored. So a rewrite with identical output and a wrong exit status passed as
  MATCH. That is a real fidelity hole: lsof exits 1 on "no matching open files"
  and shell scripts branch on it (`lsof -t … || echo none`); winlsof itself had a
  documented exit-code-capture bug (commit `3a56937`). A harness that blesses the
  wrong status defeats the point of a differential.
- **Kit change:** the verdict is now `stdout_match AND exit_match`; an exit-only
  difference DIVERGEs with a note naming both codes; `--ignore-exit` opts out for
  tools without stable statuses. Pinned with a self-test (same stdout + different
  exit → DIVERGE; `--ignore-exit` → MATCH). PLAYBOOK Phase 4 gate 2 updated.
- **Section amended:** harnesses/differential/diff_run.py (`compare`, CLI,
  self-test); PLAYBOOK · Phase 4 gate 2.

## 005. Path-scope CI, or unrelated changes make PRs look "unstable"

- **Date:** 2026-07-05
- **Codebase:** winlsof / lsof — the repo's own CI, found while landing the kit
- **What happened:** The kit's PR merged from GitHub `mergeable_state: "unstable"`.
  Nothing was failing — all checks went green — but the C project's `build.yml`
  (a full autotools `configure`/`make`/`make check`/`distcheck` on ubuntu-24.04 +
  ubuntu-22.04 + macOS) triggered on **every push/PR with no path filter**, so a
  *docs-and-scripts-only* `porting-kit/` change (and every `winlsof/` change,
  which already has its own path-scoped CI) kicked off three heavyweight C builds
  and left the PR "unstable" until they drained. Wasted CI, and a merge state that
  reads as broken when it isn't. `mergeable_state: "unstable"` means *pending or
  failing non-required checks* — not necessarily failure.
- **Kit change:** added `paths-ignore: ['porting-kit/**', 'winlsof/**']` to the
  C workflow's `push` and `pull_request` triggers (mirroring the path-scoping the
  Rust CI already used), and taught the kit's CI template to scope each
  language/subtree's workflow to its own paths. In a gradual port — where C and
  Rust coexist in one repo — an unscoped `on: [push]` runs the heavy build on
  changes it cannot affect; scope it.
- **Section amended:** harnesses/ci/porting-ci.template.yml (`on:` triggers);
  the `porting-kit-audit` skill (CI-hygiene gate). General rule for PLAYBOOK ·
  Phase 3 (skeleton/CI): scope every workflow to the paths it actually builds.

## Meta — three dry-run passes, three distinct classes of gap

Running the kit against lsof's *actual* code three times (LESSONS #2–#4) found
three different failure classes, none of which the paper Phase-3 pass (#1) caught
— because #1 was a walk of the retrospective's narrative, and these only appear
when you *execute the harnesses against the real codebase*:
- **#2 — too noisy to trust:** a scanner with 828 false positives is muted.
- **#3 — claimed but unwired:** an unsafe-fn doc gate delegated to a lint nobody
  enabled.
- **#4 — checks less than it captures:** a differential that reads exit codes but
  judges on stdout alone.
The lesson about the lessons: **a dry-run that doesn't run the tools against the
real target is theater.** All three gaps were in the *harnesses* (the kit's own
code), not the playbook prose — evidence that a kit is only as good as its tools
are exercised. `PROMPTS/90-retrospective.md` already says "run against the real
code"; these passes prove that half is where the findings live, and it is now
the emphasized half.

---

## 006. Gates fail open on "nothing ran" — self-test the degenerate case, not just detection

- **Date:** 2026-07-19
- **Codebase:** the Porting Kit itself (full-repo code review + fix pass; PR #1
  of the lifted `c2rust-port` repo, 26 findings, all fixed)
- **What happened:** All six High findings were safety gates that *passed when
  nothing meaningful ran* — and `make check-kit` was green through every one of
  them. Both binaries timing out produced identical `<<TIMEOUT>>` sentinels and
  a `MATCH` verdict (a faithfully re-ported hang — the kit's founding bug class
  — sailed through the liveness backstop PLAYBOOK explicitly promised would
  fail it). `golden.py` enshrined a hung oracle's `<<TIMEOUT>>` as golden truth
  and dropped the exit-code half of the verdict on exactly the
  oracle-substitution path it exists for. The scanner's skip-`*`-lines
  heuristic silently never scanned `*out = malloc(a * b);`. The CI template's
  fuzz job looped over an empty `cargo fuzz list` and reported green with zero
  targets, and its sanitizer job could never succeed (no `rust-src` for
  `-Zbuild-std`) — an always-red gate that would have been deleted, not fixed.
  The pattern: every self-test proved its tool *detects* the bad case it was
  built for; none proved the tool *refuses to pass* when its inputs degenerate
  (a hang on both sides, an empty target list, a missing component). Detection
  was tested; fail-closed was not.
- **Kit change:** every hole fixed with the degenerate case pinned in the same
  change: rust-side/both-side timeouts are a non-ledgerable `TIMEOUT` verdict;
  capture refuses a timed-out golden; `.rc` sidecars restore exit-code
  fidelity; real comment masking replaces the `*`-prefix skip; the fuzz CI job
  fails on an empty target list; sanitizers install `rust-src`. The general
  rule — **a gate that finds nothing to check must fail, not pass; add the
  degenerate-input case to its self-test in the same change** — is now in the
  playbook, and the retrospective prompt's step 0 requires probing each gate's
  fail-closed behavior, not just its signal-to-noise.
- **Section amended:** PLAYBOOK · cross-cutting controls ("Gates fail closed");
  PROMPTS/90 · step 0; harnesses/differential/diff_run.py,
  harnesses/golden/golden.py, harnesses/c-flaw-scan/scan_c_flaws.py,
  harnesses/ci/porting-ci.template.yml (+ their self-tests).

---

## 007. Documented commands are code — phantom flags and paste-broken examples drift silently

- **Date:** 2026-07-19
- **Codebase:** the Porting Kit itself (same review pass)
- **What happened:** The operative docs promised behavior the tools did not
  have, and nothing could catch it: `diff_run.py`'s own docstring advertised a
  `--update-ledger` flag that was never implemented; the scanner's header
  listed an `unchecked-malloc` (CWE-690) category with no corresponding check;
  `progress.py`'s usage line showed `set MODULE GATE --file F` — an order its
  argparse rejected with exit 2; CLAUDE.md's canonical smoke-test command
  (`make -C porting-kit check-kit`) failed in the kit's own repo; and the gate
  chain said "all six" while listing five. The kit already knew this failure
  class for *skills* (`check_skills.py` hard-fails dangling paths) but had no
  equivalent for the docs' *flag/CLI claims* — the paste-able surface agents
  actually execute.
- **Kit change:** every drifted claim fixed, and the class got a mechanical
  gate: `harnesses/doc-check/check_doc_flags.py` (wired into `make check-kit`)
  attributes each `--flag` in the operative docs to the nearest preceding
  harness name on the line and hard-fails if the flag is absent from that
  script's source — it would have caught `--update-ledger` on day one.
  Corollary lived immediately: the OPERATING-GUIDE backlog stopped naming
  precise flags for unimplemented features (the phantom pattern at birth).
- **Section amended:** harnesses/doc-check/check_doc_flags.py (new); Makefile ·
  check-kit; README · harness table; OPERATING-GUIDE · backlog #3/#9;
  progress.py CLI + docstring; scan_c_flaws.py docstring; diff_run.py usage;
  CLAUDE.md · gates + smoke-test command (and every SKILL.md integrity footer).

---

## 008. An acceptance list that matches by name becomes a permanent mute button

- **Date:** 2026-07-19
- **Codebase:** the Porting Kit itself (same review pass)
- **What happened:** The divergence ledger suppressed by *case name alone*:
  once `json-format` was ledgered for an intentional fix-of-C-defect, any
  future, unrelated regression in that case — wrong values, new crash output —
  reported `DIVERGE(ledgered)` and exited 0, forever. The most-exercised cases
  are the most likely to be ledgered, so the differential gate was weakest
  exactly where behavior changes most. This generalizes: any allow-list entry
  that names a *thing* rather than an *instance* (a case, a file, a finding
  id) rots from "we accepted this divergence" into "we no longer look at this
  case."
- **Kit change:** ledger entries can pin the accepted divergence's fingerprint
  — `- [x] <case> [sha256:<12-hex>]: <why>` — hashed over the normalized diff
  text. A pinned case re-fails with an explicit "the divergence changed;
  re-triage" when the diff no longer matches; unpinned (legacy) entries still
  suppress but the tool prints the exact pin to add. Pin-accept and
  stale-pin-refail are self-tested.
- **Section amended:** harnesses/differential/diff_run.py (`load_ledger`,
  `compare`, output hint, self-test); skeleton/DIVERGENCES.md · format.

---

## 009. A template must pass the gates it ships — or every copy starts red

- **Date:** 2026-07-20
- **Codebase:** the Porting Kit itself (installing real CI for the kit repo; PR #3)
- **What happened:** Wiring meaningful CI meant running the kit's own gates, and
  the shipped **skeleton did not pass them**. It was not `cargo fmt`-clean, and its
  example parser/CLI used `i + 1` on loop indices — which trips the workspace's own
  `clippy::arithmetic_side_effects` lint under `-D warnings`. Both `cargo fmt
  --check` and `cargo clippy --all-targets -- -D warnings` are in the kit's CI
  template, so a fresh copy of the skeleton started **red** under the kit's own CI:
  a starting-point that fails the gates it configures. Nothing caught it because
  `make check-kit` is toolchain-free and never built or linted the skeleton — the
  one artifact every port begins by copying was the one artifact no gate checked.
  Same family as #6/#7: the kit's own artifacts must satisfy the kit's own rules.
- **Kit change:** (a) fixed the skeleton to a clean exemplar — fmt-clean, and
  `i.saturating_add(1)` (the checked/saturating idiom the playbook prescribes, so
  the skeleton now *models* its own lint instead of violating it); (b) added
  `harnesses/skeleton-check/check_skeleton.sh` to `make check-kit` — it runs the
  real fmt/clippy/build/test when a Rust toolchain is present and SKIPs cleanly
  otherwise, so a skeleton regression is caught locally even where CI can't run,
  without breaking check-kit's python3+bash-only minimum; (c) Phase 3 exit criteria
  now require the workspace/skeleton to pass the gates it configures.
- **Section amended:** skeleton/crates/{core,cli}; harnesses/skeleton-check/
  check_skeleton.sh (new) + Makefile · check-kit; README · harness table;
  PLAYBOOK · Phase 3 exit criteria.

---

## 010. CI runs in the target's GitHub, not yours — and "it didn't start" isn't "it failed"

- **Date:** 2026-07-20
- **Codebase:** the Porting Kit itself (same CI-install pass)
- **What happened:** The first kit-repo CI workflow concluded `startup_failure`
  with **zero jobs** — twice, then again after simplification. Diagnosis: it used
  third-party actions (`dtolnay/rust-toolchain`, `actions/setup-python`), and a
  repo whose Actions policy allows only first-party `actions/*` **fails the whole
  run at compile time**, before any step. Two traps, both new: (1) a workflow that
  leans on third-party actions is **not portable** to a policy-restricted repo — the
  action is a dependency the target environment can block; (2) `startup_failure`
  *reads* like a red test result but is infra/policy — merging on it would be wrong
  in both directions (don't merge red code; don't treat unrunnable-CI as failing
  code). Even a `checkout`-only workflow startup-failed here, so this repo's Actions
  are blocked outright. The kit's own `porting-ci.template.yml` uses third-party
  actions and would hit this in such a repo. Meta-mirror of #2–#4: a CI config only
  proves itself when run in the **actual target repo's** GitHub — a green run in a
  different environment teaches nothing about a restricted one.
- **Kit change:** the kit-repo CI (`.github/workflows/check-kit.yml`) uses only
  `actions/checkout` + the runner's preinstalled make/python3/rustup via `run:`
  steps, so no third-party `uses:` can fail startup; documented the failure mode and
  this `checkout`-only fallback in the CI template header and OPERATING-GUIDE §5 #5.
  (When CI genuinely can't run in a repo, the toolchain-optional `make check-kit` +
  skeleton gate from #9 is the standing local gate.)
- **Section amended:** .github/workflows/check-kit.yml (new); harnesses/ci/
  porting-ci.template.yml (portability caveat); OPERATING-GUIDE · §5 #5.

---

## 011. A process-driving harness must be hermetic — control stdin, don't inherit it

- **Date:** 2026-07-20
- **Codebase:** the Porting Kit itself (found while validating the perf gate, #P0)
- **What happened:** `run_one` — the shared runner behind the differential, golden,
  diff-fuzz, perf, and cando harnesses — passed no stdin for a case without a
  `stdin` key, so the child **inherited the parent's stdin**. A stdin-reading binary
  (the skeleton `port` reads stdin unconditionally) then blocked forever on an
  interactive/TTY parent: a differential/perf run that hangs or passes depending on
  *who launched it*. Latent since the differential shipped; it only surfaced when
  the new perf gate ran a real stdin-reading binary from an interactive shell. This
  is the hostile-host rule (#1) extended from encoding/quoting to the process-launch
  surface — inherited fds/stdin/env are ambient state a test harness must not depend
  on.
- **Kit change:** `run_one` now feeds `subprocess.DEVNULL` when a case provides no
  stdin (deterministic EOF, hermetic), pinned in the diff_run self-test; all five
  consumers stay green. Generalized in the playbook: a harness that spawns processes
  controls stdin/env/cwd explicitly and inherits nothing.
- **Section amended:** harnesses/differential/diff_run.py (`run_one` + self-test);
  PLAYBOOK · Phase 2 "harden the harness for its host".

---

## 012. Two streams on one trunk build the same thing twice — reconciliation is a real cost line

- **Date:** 2026-07-22
- **Codebase:** the Porting Kit itself (project retrospective, snapshot → v1.0)
- **What happened:** Two agent sessions worked the same backlog concurrently from
  different base commits. Both independently implemented the P0 library
  differential and the P0 performance gate; PR #3 merged first, so the parallel
  stack (#5–#8) collided and had to be **replayed** onto the moved `main` by a
  dedicated reconcile PR (#9) that adjudicated winners (kept `cando` + `perf`,
  dropped the duplicate `perf-gate/`, landed `lib_diff` as a complement) and
  closed four PRs unmerged. Aftercost: the replay re-committed everything, so
  `git cherry`/patch-id later reported the superseded branches as "unmerged" —
  merged-or-not became manual forensics before the branches could be safely
  deleted. Honest upside: the two library differentials differed by *approach*
  (driver-subprocess vs ctypes) and were kept as deliberate complements — the
  kit's own "two candidate translations, let the suite pick" advice, arrived at
  by accident.
- **Kit change:** none mechanical (this is process, not tooling): parallel
  streams on one trunk need either serialization or an explicit file-ownership
  partition agreed up front; a reconcile that replays commits must record its
  keep/drop decisions in the PR/commit message (PR #9 did — that record is what
  later made branch cleanup safe); and duplication, when it happens, should be
  triaged for *diversity value* before one copy is discarded. Recorded in the
  project retrospective's plan as standing discipline.
- **Section amended:** RETROSPECTIVE-kit-v1.md · §3/§5 (the durable statement);
  no harness/playbook change.

---

## 013. A recorded lesson is not a control — new code recurred two logged lessons

- **Date:** 2026-07-22
- **Codebase:** the Porting Kit itself (project retrospective, step 0 against
  `examples/adler32`)
- **What happened:** The v1.0 exit test — written *after* LESSONS #6 and #8 were
  logged — shipped with both lessons violated: it **failed open** (`set -uo`
  without `-e`, and a `cargo test … | grep … || true` that swallowed test
  failures, so any gate failure still printed the success banner and exited 0),
  and its generated ledger used **name-only, unpinned** entries (`lib_diff`
  printed the pin-me warning on every run, unheeded). Neither recurrence was
  caught by reading; both surfaced only when this retrospective *executed* the
  example and probed its degenerate case (ledger emptied → must abort). Writing
  a lesson down does not apply it to the next artifact; only gates and
  checklists do.
- **Kit change:** the exit test now fails closed (`set -euo pipefail`,
  capture-then-check on `cargo test`; probed: unledgered divergence → exit 1, no
  banner), its ledger entries are fingerprint-pinned, and it runs as a third job
  in `.github/workflows/check-kit.yml` so it cannot rot unexecuted.
  `PROMPTS/90-retrospective.md` (and the retrospective skill) now instruct:
  review every NEW or changed kit artifact against the LESSONS list before
  merge — each entry is a checklist item, not history.
- **Section amended:** examples/adler32/run.sh (fail-closed + pinned ledger);
  .github/workflows/check-kit.yml (exit-test job); PROMPTS/90 · step 3;
  skills/porting-kit-retrospective.
