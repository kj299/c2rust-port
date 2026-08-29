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

**A lesson that amends kit code must be pinned in that code's smoke test** —
the citation `LESSONS #N` goes next to the pinned self-test check / changed
logic, and `make check-kit` enforces the linkage mechanically
(`harnesses/doc-check/check_lessons_pinned.py`): a new entry naming a harness
fails the build until the harness cites it, and a later rewrite that drops the
pin fails until the lesson is re-pinned. That is what keeps this file a set of
controls instead of a set of memories (LESSONS #13).

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
  merge — each entry is a checklist item, not history. And the lesson↔smoke-test
  linkage itself is now mechanical: `check_lessons_pinned.py` (in `make
  check-kit`) hard-fails any lesson whose `Section amended` names a harness
  that no longer cites `LESSONS #N` — its first real run found six aged links
  (lessons numbered at retro time, after their code landed), all re-pinned.
- **Section amended:** examples/adler32/run.sh (fail-closed + pinned ledger);
  .github/workflows/check-kit.yml (exit-test job);
  harnesses/doc-check/check_lessons_pinned.py (new) + Makefile · check-kit;
  LESSONS.md · format header; PROMPTS/90 · step 3;
  skills/porting-kit-retrospective.

---

## 014. An allow-list must ASSERT the accepted state, not merely SUPPRESS it

- **Date:** 2026-07-24
- **Codebase:** the Porting Kit itself (comprehensive multi-lens audit → v1.x)
- **What happened:** A six-lens adversarial audit found the deepest hole in the
  whole kit, in the v1.0 exit test itself: **a ledgered divergence is pure
  suppression — it never asserts the divergence still occurs.** A ledger entry
  says "this case intentionally differs from C because we fixed a C bug," yet
  `compare_one` evaluated `MATCH` *before* `name in known`, so if a ledgered case
  *stopped* diverging it was silently downgraded to `MATCH` and passed. Reverting
  the adler32 overflow fix with `wrapping_add` (C-identical output — what a dev
  "matching C" writes) made the flagship exit test go **green, full success
  banner, exit 0**, in BOTH library differentials. The port's entire reason to
  exist could be deleted and every gate stayed green. This is distinct from #8
  (which pins a *changed* divergence): #8 caught a divergence that *mutated*; this
  is a divergence that *vanished*. The fingerprint pin never fires on a vanish,
  because there is no divergence left to fingerprint. Generalizes: any allow-list
  entry (a ledgered divergence, a suppressed lint, an ignored advisory, an
  expected-failure test) that only *suppresses* rots into a blind spot — it must
  also *assert* that the condition it accepts is still present, or accepting a
  thing becomes not-looking-at it.
- **Kit change:** a ledgered case that now MATCHes is a new **`LEDGER-STALE`**
  verdict — a hard failure (never passes, never ledgerable), in the shared
  `compare_one` (diff_run + cando + diff-fuzz) and independently in `lib_diff`'s
  `compare_call` (it has its own comparison path — the fix had to be applied
  twice, which is itself why the audit checked *both* differentials). Pinned in
  three self-tests and proven end-to-end: reverting the adler32 fix now fails the
  exit test. **Same audit, recurrences of #6 (fail-closed) fixed and cited in
  place, not minted as new lessons:** an empty/mis-keyed matrix made every
  differential exit 0 over a wrong binary (now refused); invalid-UTF-8 stdout
  collapsed to `MATCH` via `decode(replace)` → U+FFFD (now `backslashreplace`,
  bytes stay distinct); the fuzzer latin-1-decoded then utf-8-re-encoded its bytes,
  never feeding the high bytes it targets (now `stdin_bytes`, verbatim); a
  `SAFETY:` substring inside a string literal passed the unsafe gate (now checked
  in a real comment span); and `scan_c_flaws` had no `memcpy`/`memmove` check and
  missed pre-computed overflow (`t=n*w; malloc(t)`) and a UAF across a nested
  block — a Phase-0 scanner reporting "0 flaws" on vulnerable C (all added). And
  the pass tripped one more, in the gate that enforces *this very field*: the
  lessons-pinned check (LESSONS #13) silently skipped any `Section amended` path a
  markdown line-wrap split after a `/` (`harnesses/cando/`⏎`cando_diff.py`) —
  matching neither half — so `audit_unsafe.py` here went unchecked until it too
  was flagged. The extractor now rejoins wrapped paths (pinned self-test); the gate
  meant to make pinning fail-closed had itself been failing open.
- **Section amended:** harnesses/differential/diff_run.py (`compare_one`
  LEDGER-STALE + `run_one` byte fidelity + `load_matrix` empty-guard);
  harnesses/library-differential/lib_diff.py (`compare_call`);
  harnesses/cando/cando_diff.py; harnesses/diff-fuzz/diff_fuzz.py;
  harnesses/unsafe-audit/audit_unsafe.py;
  harnesses/c-flaw-scan/scan_c_flaws.py;
  harnesses/doc-check/check_lessons_pinned.py (rejoin wrapped paths + self-test);
  and RETROSPECTIVE-kit-audit.md (the finding inventory + the v1.x backlog of
  what was NOT fixed).

---

## 015. An inherited environment constraint is a dated observation, not a fact

- **Date:** 2026-07-25
- **Codebase:** the Porting Kit itself (v1.x backlog burn-down)
- **What happened:** The comprehensive audit (LESSONS #14) shipped a **false claim
  about the present**, and it was one this session inherited rather than checked.
  Earlier sessions established that GitHub Actions was policy-blocked in this repo
  (every run a `startup_failure`, zero jobs — LESSONS #10), and that fact was
  reasonably carried forward: `RETROSPECTIVE-kit-v1.md` §5 and then
  `RETROSPECTIVE-kit-audit.md` §5/§6 both asserted the workflows "have never
  executed." Within the hour of the audit merging, the very PR carrying it went
  **green on all three CI jobs** — Actions had been enabled at some point and
  nobody re-checked. The audit's own headline discipline is "execution beats
  reading," and it had just published an unexecuted claim about execution. The
  generalization is the uncomfortable half: a *negative* environment finding ("X
  doesn't work here," "the API is unavailable," "that tool isn't installed") is
  the kind of fact most likely to be inherited across sessions and least likely to
  be re-tested, because re-testing looks redundant and the claim is usually still
  true. It ages silently, and unlike a wrong lint or a bad pin, **no gate watches
  prose**. It also biases the backlog: an item filed as "blocked by the
  environment" stops being attempted, so the constraint outlives itself.
- **Kit change:** no new harness — this is a *documentation-integrity* lesson and
  the honest move is a convention, not machinery I'd be pretending enforces it.
  (1) Environment claims in kit docs are now written **dated and scoped** ("as of
  YYYY-MM-DD, in this repo") rather than as standing facts. (2) Superseded claims
  are corrected by an in-place **dated correction note**, never a silent rewrite —
  `RETROSPECTIVE-kit-v1.md` gains a status note and `RETROSPECTIVE-kit-audit.md`
  §5 keeps its wrong sentence visible above the correction, so the failure mode
  stays legible instead of being erased. (3) `PROMPTS/90-retrospective.md` step 0
  now says: before repeating any inherited "this doesn't work here" claim,
  **re-run the thing** — the cost is one command and the failure mode is publishing
  a falsehood in the document that exists to be trusted.
- **Section amended:** RETROSPECTIVE-kit-v1.md · status note;
  RETROSPECTIVE-kit-audit.md · §5 correction + §6 burn-down;
  PROMPTS/90-retrospective.md · step 0.

---

## 016. A multi-defect fixture pins only the union — mutate the gates to prove them

- **Date:** 2026-07-25
- **Codebase:** the Porting Kit itself (gate-mutation verification, the standing
  `RETROSPECTIVE-kit-v1.md` §5 item 2)
- **What happened:** Every fail-open this kit has ever shipped — the both-hang
  MATCH, LEDGER-STALE, the wrapped-path skip, the fenced-block harvest — was a
  gate that *passed while checking nothing*, and every one was found by a human
  probing by hand. The gate-mutation harness makes that probe mechanical:
  neutralize each gate's crown verdict in a scratch copy (`is_match = True`,
  `return []`, `if False:`) and require its own self-test to go red. **Its first
  sweep found a survivor.** `check_skills.py`'s missing-path detection could be
  deleted outright with the suite staying green, because its "bad skill" fixture
  bundled TWO defects — a name mismatch and a missing path — into one
  `exit == 1` assertion: the name mismatch alone drove the exit code, so the
  path check was pinned by nothing. The general form: **a fixture that carries N
  defects pins only their union — any N−1 of the checks can silently die.** The
  sweep also showed diff-fuzz's self-test *crashing* (unguarded `findings[0]`)
  instead of failing when findings vanish; crash-red is indistinguishable from
  harness-broken-red, so the mutation harness treats a Traceback as a hard
  error, not a catch.
- **Kit change:** `harnesses/gate-mutation/mutate_gates.py` — a 14-gate mutation
  table wired into `make check-kit` (self-test + full sweep). Fail-closed at
  every joint: a stale or ambiguous table entry, a syntax-breaking mutation, a
  Traceback under mutation, or a red baseline are all hard errors, so the sweep
  can neither rot silently nor claim fake coverage. The survivor was fixed by
  splitting the bundled fixture (one fixture per defect, each pinned
  independently) and the diff-fuzz self-test now fails cleanly on zero findings.
  14/14 mutations caught; the gate set is self-verifying.
- **Section amended:** harnesses/gate-mutation/mutate_gates.py (new);
  skills/check_skills.py (one fixture per defect);
  harnesses/diff-fuzz/diff_fuzz.py (guarded `findings[0]`);
  Makefile · check-kit; README · harness table;
  RETROSPECTIVE-kit-audit.md · §6 burn-down.

---

## 017. The C is a SPEC, and only the oracle knows what it says

- **Date:** 2026-07-25
- **Codebase:** cJSON v1.7.18 (C JSON parser → Rust) — the kit's first FOREIGN port
- **What happened:** Every non-trivial behavior I got *wrong* on the first try, I
  got wrong by **reasoning about what the C must do** instead of **running it**.
  Four instances, all caught by executing the oracle, none findable by reading:
  1. **`print(DBL_MAX)` is lossy.** I wrote the unit test asserting the reasoned
     answer (15 digits can't round-trip DBL_MAX → the 17-digit fallback fires).
     The oracle refuted it: the `%1.15g` form `1.79769313486232e+308` reparses as
     **inf**, and cJSON's `compare_double(inf, d)` = `|inf−inf| ≤ inf·ε` =
     `nan ≤ inf` = **true**, so the C *accepts* the failed round-trip and keeps
     the lossy form — and `print → reparse → print` yields `null`.
  2. **`cJSON_Compare` says a value ≠ its own duplicate** for an inf/nan number
     (same `compare_double` quirk) and for any object with **duplicate keys** (the
     O(n²) first-match lookup can't resolve the second key). Surfaced by the
     `dup-eq` matrix's C-baseline validation, which *refused my vectors* because
     they asserted `"true"`.
  3. **`cJSON_Minify` doesn't track escape parity** — a `\` before a `"` escapes
     that quote even when the backslash is itself escaped, so `"\\" "` keeps its
     space. My "correct" escape-tracking implementation dropped it. Found by
     differential fuzzing, not by reading `minify_string`.
  4. **`parse_hex4` returns 0 on INVALID hex**, so `"\uZZZZ"` parses as a NUL
     byte rather than failing; and the printer then truncates at that NUL.
  The through-line: a mature C library's observable behavior is a **thicket of
  accreted quirks**, several of which look like bugs and some of which *are* — and
  a port that "cleans them up" silently is not safer, it is *differently wrong*.
  Faithfulness is a decision to make per-quirk with the C's actual bytes in hand.
- **Kit change:** `PROMPTS/40-port-module.md` and the module skill now open with
  **probe-then-port**: before writing a module, run the oracle on its edge cases
  and paste the observed bytes into the module's doc comment; write unit-test
  expectations from that transcript, never from reasoning about the C source. The
  kit already said "execution beats reading" for *harness* validation (LESSONS
  #13/#15); this extends it to the **translation act itself**. `PLAYBOOK.md` Phase
  4 gains the same line as an entry criterion.
- **Section amended:** PROMPTS/10-module-port.md · step 0; PLAYBOOK · Phase 4
  entry criteria; skills/porting-kit-module/SKILL.md; RETROSPECTIVE-cjson.md · §2.

---

## 018. A gate that has nothing to check is not a passing gate

- **Date:** 2026-07-25
- **Codebase:** cJSON port — the `unsafe-audit` and `sanitized` gates
- **What happened:** For six of the port's seven increments, `audit_unsafe.py`
  reported **"unsafe blocks: 0, documented: 0, undocumented: 0" and exited 0** —
  and I read that as the gate passing. It wasn't: the safe core is
  `#![forbid(unsafe_code)]`, so there was **nothing for that gate to audit**, and
  its green was structurally uninformative right up until the FFI crate landed
  (33 blocks, all documented — the first run where the gate said anything). The
  same shape, worse: I asserted "miri/asan need toolchains this environment
  lacks" across five increments and left `sanitized` unset — **an inherited
  environment claim I never re-tested**, which is precisely LESSONS #15, written
  by me, in this same session. The retrospective's step-0 probe took one command:
  `rustup toolchain install nightly --component miri` **succeeded**, miri ran
  clean over the port, and the gate I'd written off as impossible was available
  the whole time. The generalization is sharper than "re-verify claims": a gate
  reporting **0 of 0** and a gate **not installed** are the same failure — a
  *believed-covered* control that inspected nothing — and both render as green.
- **Kit change:** `audit_unsafe.py` now reports `NOTHING-TO-AUDIT` when it finds
  zero blocks across the scanned paths (still exit 0, but never silently
  green-looking) and its `--json` carries `"blocks_found": 0`, so
  `progress.py ingest` can refuse to advance `unsafe_audited` on a vacuous
  report. The port's `check.sh` models the discipline for a gate that cannot run
  here: miri is toolchain-OPTIONAL and **`sanitized` advances only when miri
  actually ran** (never on a SKIP), with nightly+miri added to the CI job so it
  runs for real. Verified fail-closed both ways: clean code passes; an injected
  out-of-bounds read makes miri exit nonzero.
- **Section amended:** harnesses/unsafe-audit/audit_unsafe.py (NOTHING-TO-AUDIT +
  `blocks_found`); harnesses/progress/progress.py (`_clean_unsafe` refuses a
  0-block report); ports/cjson/check.sh; .github/workflows/check-kit.yml;
  RETROSPECTIVE-cjson.md · §3.

---

## 019. Scope each increment's differential to what it can decide

- **Date:** 2026-07-25
- **Codebase:** cJSON port — the module-tagged corpus
- **What happened:** The kit's loop says "every module is diffed against the
  oracle the moment it lands," but a 7-module port has a period where the Rust
  **cannot parse most of the corpus** — module 2 lands and 60 of 79 vectors
  involve strings, arrays, or objects that don't exist yet. Running the full
  matrix would fail them all for "not ported yet," which is **schedule, not
  divergence** — noise that trains you to ignore red, the LESSONS #2 failure mode
  in a new place. Tagging each vector with the modules whose behavior determines
  it (`mods: ["scalar"|"string"|"tree"|"minify"]`) and emitting
  `matrix-ported.json` = "every case my ported modules fully decide" made each
  increment's differential **meaningful and 100% green**, growing 25 → 44 → 69 →
  79 as modules landed. The corpus is written ONCE against the C (all 86 vectors
  validated up front); only the *filter* moves.
- **Kit change:** `PLAYBOOK.md` Phase 2 now prescribes tagging corpus vectors by
  the module(s) that decide them and running each increment against the
  ported-subset filter, with the full matrix as the cutover gate;
  `PROMPTS/20-oracle.md` and the oracle skill carry the recipe.
  `ports/cjson/oracle/gen_corpus.py` is the worked reference implementation.
- **Section amended:** PLAYBOOK · Phase 2 "Do"; PROMPTS/00-new-port-kickoff.md;
  skills/porting-kit-oracle/SKILL.md; ports/cjson/oracle/gen_corpus.py (the worked
  reference); RETROSPECTIVE-cjson.md · §4.

---

## 020. A harness meets its real bugs only on a real port

- **Date:** 2026-07-25
- **Codebase:** cJSON port — `lib_diff.py`
- **What happened:** `lib_diff` had a full self-test suite, survived the
  gate-mutation sweep, and had driven the adler32 example end-to-end. It still
  **crashed** the first time a real port used it: the cJSON FFI vectors include
  `cJSON_Version`, a `cstr`-returning function, and `--json` died in
  `json.dumps` because `c_ret`/`rust_ret` held raw `bytes`. Nothing in the kit's
  own tests had ever exercised a bytes-valued return *through the JSON report* —
  the self-tests checked verdicts, the mutation sweep checked the verdict logic,
  and the example's vectors all returned integers. Coverage of the *decision* is
  not coverage of the *plumbing around it*, and the gap only shows when a foreign
  port picks a combination the kit's authors never wrote down.
- **Kit change:** fixed (`_jsonable` backslashreplace-decodes bytes, keeping the
  report serializable AND byte-faithful per LESSONS #14) and pinned in the
  self-test. Standing discipline added to `PROMPTS/90-retrospective.md`: a port
  that *uses* a kit harness in a new shape must send the resulting harness fix
  back to the kit in the same session — this is the compounding loop's actual
  mechanism, and it only fires when the kit is exercised by code it did not
  author.
- **Section amended:** harnesses/library-differential/lib_diff.py (`_jsonable` +
  self-test); PROMPTS/90-retrospective.md · report-back discipline;
  RETROSPECTIVE-cjson.md · §5.

---

## 021. Generate test expectations from the oracle — a convention is not a control

- **Date:** 2026-07-25
- **Codebase:** the kit itself (post-cJSON), closing RETROSPECTIVE-cjson.md §6
- **What happened:** LESSONS #17 established probe-then-port as a *convention*:
  run the C on the module's edge cases, paste the transcript, write expectations
  from it. But every §2 mistake on the cJSON port had already shown what happens
  without enforcement — wrong unit tests written from reasoning happily agreed
  with wrong Rust until a gate outside the tests disagreed — and LESSONS #13 is
  explicit that conventions decay: two logged lessons recurred in code written
  after them. Nothing stopped the *next* port's author from hand-writing an
  expectation that contradicts the C, or from quietly editing a pasted
  transcript to match their code.
- **Kit change:** `harnesses/probe/probe.py` mechanizes the convention end to
  end: `run` executes the probes against the C oracle and pins the observed
  (rc, stdout) byte-faithfully under a fingerprint; `gen` **generates** the Rust
  `#[test]` expectations from the transcript (one hand-written glue fn maps
  driver modes to the crate's API — the expectations themselves are never
  hand-written, so one that contradicts the C cannot exist); `verify` fails
  closed on oracle drift (every probe re-run, behavior re-compared — never
  hash-trusted), on a tampered transcript (fingerprint), and on a hand-edited
  or stale generated file (byte-compare against a fresh regeneration).
  Fail-closed per the kit's characteristic bug: zero probes, a hanging oracle,
  and a missing artifact are all failures, never passes. Wired: `make check-kit`
  self-test, a gate-mutation entry (neutralized drift-verdict → self-test red),
  and the worked integration — the cJSON port's eight §2 quirks are now pinned
  in `ports/cjson/oracle/probes-quirks.json`, generated into
  `crates/core/tests/probes_quirks.rs`, and verified in `ports/cjson/check.sh`
  step 1b.
- **Section amended:** harnesses/probe/probe.py (the harness + self-test);
  harnesses/gate-mutation/mutate_gates.py (probe entry); ports/cjson/check.sh
  (step 1b); PLAYBOOK · Phase 4 entry criteria; PROMPTS/10-module-port.md ·
  step 0; skills/porting-kit-module/SKILL.md · step 0.

---

## 022. A gate that can never pass is as broken as one that can never fail

- **Date:** 2026-08-22
- **Codebase:** the kit itself — `harnesses/sanitizers/run_sanitizers.sh`,
  `harnesses/gate-mutation/mutate_gates.py`
- **What happened:** `run_sanitizers.sh ubsan` ran
  `RUSTFLAGS=-Zsanitizer=undefined`. **rustc has no `undefined` sanitizer** —
  Rust's UB detector is miri — so the mode exited 1 on every codebase in the
  world, and `all` (which included it) was **permanently red no matter how clean
  the code**. The kit's whole doctrine is fail-closed, but a gate that cannot go
  green teaches its users to skip it, and a skipped control is a broken control.
  It survived: PR #1's 26-finding review, a whole foreign port, and **every
  gate-mutation sweep**. Three reasons, each its own hole: (1) `--check`
  validated bash *syntax* and printed `self-test: OK` — the identical root cause
  as the original never-runnable sanitizer job (LESSONS #6), recurring inside the
  very harness that lesson was about; (2) `mutate_gates._run` hardcoded
  `sys.executable`, so **no bash harness could be in the mutation table at all**
  while the sweep kept printing "15 gate(s) mutated, 0 survivor(s)" — a summary
  that reads as the whole gate set and silently covered only the python half;
  (3) the cJSON port **hand-rolled its own `cargo +nightly miri test`** instead
  of calling the harness, so in the kit's entire life this harness had never once
  executed against real code. Found by running it — `--check` says OK, the actual
  mode says rc=1.
- **Kit change:** modes now map through `is_valid_san` against the sanitizer list
  rustc accepts, `--check` pins that validator with a **negative fixture** (it
  must reject `undefined`, the exact value that shipped) and cross-checks the
  list against a live nightly rustc; `ubsan` delegates to miri with an
  explanation; `all` = miri + asan; `run_sanitizers.sh` takes `-- <cargo args>`
  so a port can scope it instead of duplicating it. `mutate_gates._run` dispatches
  by extension, making **bash gates sweep-able for the first time**, and the
  sanitizer gate is in the table. `ports/cjson/check.sh` now calls the harness
  (and adds asan, per LESSONS #15 re-probing — see below).
- **Section amended:** harnesses/sanitizers/run_sanitizers.sh (validator +
  negative fixture); harnesses/gate-mutation/mutate_gates.py (`_run` dispatch +
  sanitizers entry); ports/cjson/check.sh (calls the harness, adds asan);
  RETROSPECTIVE-probe-harness.md · §2.

---

## 023. Verifying the artifacts that exist says nothing about the one that is missing

- **Date:** 2026-08-22
- **Codebase:** the kit itself — `harnesses/probe/probe.py` (one day old)
- **What happened:** `probe.py` was built to fail closed everywhere: zero probes
  in a file is an error, a hanging oracle is an error, a tampered transcript or
  hand-edited generated test is an error. All true — and all irrelevant to the
  question nobody asked: *which probes files exist at all?* That was a hand-edited
  line in the port's `check.sh` naming one file. A module could land with **no
  probes whatsoever** and every gate stayed green, because `run`/`gen`/`verify`
  only ever see the files they are handed. The kit's characteristic 0-of-0
  (LESSONS #6/#14/#18/#20), displaced one level up into the *wiring* — committed
  by me in the same change that mechanized the lesson about conventions decaying.
  A gate hardened against everything inside its input is still trusting whoever
  chose the input.
- **Kit change:** `probe.py coverage` takes the module list from the port's own
  `progress.json` (so it cannot drift from the list the gates track) and fails
  naming any module with no probes file; an empty module list is itself a failure.
  Probes files carry `modules: [...]` tags, reusing the corpus tagging idiom of
  LESSONS #19. Wired into `ports/cjson/check.sh`. Writing the missing probes for
  the two uncovered cJSON modules immediately pinned **four behaviors reasoning
  would have gotten wrong** — cJSON accepts a leading UTF-8 BOM, accepts trailing
  garbage after a complete value (`[1] xyz` → `[1]`), treats an **embedded NUL as
  whitespace** (`buffer_skip_whitespace` tests `<= 32`), and prints an empty
  object as `{\n}` while an empty array prints `[]`. The port already matched all
  four (the differential and fuzzer had driven it there); they are now *named*, so
  a future "cleanup" of NUL-as-whitespace breaks a test instead of drop-in parity.
- **Section amended:** harnesses/probe/probe.py (`cmd_coverage` + self-test);
  ports/cjson/check.sh (step 1b coverage); PLAYBOOK · Phase 4 entry criteria;
  PROMPTS/10-module-port.md · step 0; RETROSPECTIVE-probe-harness.md · §3.

---

## 024. The one rung with no evidence is the one that outlived its proof

- **Date:** 2026-08-22
- **Codebase:** the kit itself — `harnesses/progress/progress.py`,
  `harnesses/sanitizers/run_sanitizers.sh`, `ports/cjson/check.sh`
- **What happened:** five of the six gate rungs advance by ingesting a harness's
  provenance-stamped `--json` report, and `progress.py` verifies that stamp
  against HEAD — a report from an older commit is refused as STALE. `sanitized`
  had no such report: the port's `check.sh` set it directly with `progress.py
  set`, carefully only when miri had actually run. That care was real but
  insufficient, because **nothing ever un-set it** and `progress.json` is
  committed. The claim therefore outlived the run that earned it: this session
  opened in a fresh container with **no miri installed at all**, and the cJSON
  port still read 7/7 fully gated, `sanitized` ticked. Every other rung would
  have gone stale-and-refused in that container; the hand-set one could not.
- **Kit change:** `run_sanitizers.sh --json FILE` emits a stamped report of what
  **actually ran** (`modes_run`, `rc`), using the kit's own
  `diff_run.provenance_stamp` rather than a bash reimplementation, so one change
  to how the kit proves provenance upgrades every gate at once. `progress.py`
  gains `--sanitize-json` and `_clean_sanitize`, which advances `fuzzed →
  sanitized` only when a checker genuinely ran (`modes_run` non-empty — a SKIP is
  not a clean run, LESSONS #18/#22) and exited 0. `ports/cjson/check.sh` no longer
  hand-sets the rung, and its committed `progress.json` was reset to `ported` and
  re-earned: all 7 modules climbed all four evidence rungs in one ingest. Probed
  both ways in the live port — a report from another commit is refused as STALE,
  and a correctly-stamped report where nothing ran advances nothing.
  **And the same trap one level up:** once the committed table sits at the top
  rung, the ingest advances nothing on every later run, so a rung that quietly
  stopped being provable looks identical to one that still is — the CI job's
  `ingest: advanced nothing` was hiding exactly that. `check.sh` now **replays**
  the ingest into a scratch copy seeded at `ported` and fails unless every module
  re-earns every rung from the reports that run just produced. Probed: blanking
  one module's sanitizer report leaves it stuck at `fuzzed` and the gate goes red.
- **Section amended:** harnesses/progress/progress.py (`_clean_sanitize` +
  self-test); harnesses/sanitizers/run_sanitizers.sh (`--json`);
  ports/cjson/check.sh (report-driven `sanitized`); RETROSPECTIVE-probe-harness.md · §6.

---

## 025. A hand-maintained coverage table reports on itself

- **Date:** 2026-08-22
- **Codebase:** the kit itself — `harnesses/gate-mutation/mutate_gates.py` and the
  three bash harnesses it could not see
- **What happened:** the gate-mutation sweep prints *"N gate(s) mutated, 0
  survivor(s)"*, which reads as a statement about the gate set. It is a statement
  about **the hand-written table**. Nothing required a harness to be in it, so
  the count was silently partial — and because `_run` assumed python, the missing
  ones were precisely the bash harnesses, one of which (LESSONS #22) was shipping
  a mode that could never pass. Fixing the interpreter made them *sweepable*, not
  *swept*: adding entries for the remaining three immediately produced **three
  survivors**. All three self-tests only ever exercised the happy path — an
  always-present template, an always-present config, an always-present skeleton
  dir — so neutralizing each verdict changed nothing they observed. Proves
  detection, never refusal: LESSONS #6's root cause, alive in three more places.
- **Kit change:** `coverage_gaps()` walks `harnesses/` and `skills/` for anything
  exposing a self-test and fails the sweep naming any harness with no mutation
  entry; exemptions must be written down with a reason in `COVERAGE_EXEMPT` (one
  entry: the mutator itself). The three bash gates had their crown verdict
  extracted into a predicate (`valid_target`, `have_deny_template`,
  `skel_present`) and their self-tests given **negative fixtures** — a missing or
  unexpanded target, an empty config dir, an empty skeleton dir — so each now
  goes red under mutation. Sweep: 19 gates, 0 survivors, 0 table gaps.
- **Section amended:** harnesses/gate-mutation/mutate_gates.py (`coverage_gaps` +
  self-test); harnesses/fuzz/gen_fuzz_target.sh; harnesses/supply-chain/run_supply_chain.sh;
  harnesses/skeleton-check/check_skeleton.sh; RETROSPECTIVE-probe-harness.md · §6.

---

## 026. A gate judges only the surface the driver exposes

- **Date:** 2026-08-29
- **Codebase:** cJSON port, module 8 (`ffi-builder`) — found while porting the
  builder/query surface
- **What happened:** `cJSON_GetArraySize` counts a node's CHILDREN whatever the
  node is — the C walks `child`/`next`, so an *object* reports its member count.
  The port's version said "array length, else 0", written from reasoning about
  the function's name — and it shipped through **all six gates** and sat on
  `main` at cutover, fully ticked, with the divergence live. Nothing caught it
  because no differential driver mode ever *called* the accessor: the driver
  exposed parse/print/minify/dup pipelines, so "the differential is 79/79 green"
  was a statement about those pipelines, not about the API the module claims.
  The probe harness caught it the moment module 8's `query` mode put the
  accessor on the observable surface (`{"a":{"b":1}}` → C says `size=1`).
  This is the kit's characteristic bug at a **sixth altitude**: after the
  verdict (#6), the input (#14/#18/#20), the wiring (#23), the tool inventory
  (#22), and inherited state (#24) — now the *observable surface itself*. A
  gate hardened against everything it can see says nothing about what it was
  never shown.
- **Kit change:** module 8's `build`/`query` driver modes put the builder,
  query, predicate, and struct-field surface on the compared contract, each
  side implemented ONCE (`crates/core/src/modes.rs`, `oracle/cjson_modes.c`)
  so the executable and ABI tests cannot drift; the fix is pinned by the
  generated `probe_query_object` test (reverting it goes red — verified).
  Discipline, wired into the prompts: PLAYBOOK Phase 4 and PROMPTS/10 step 0
  now require the module's driver modes to cover **every public entry point
  the module claims** before the module may advance — an accessor the driver
  cannot reach is ungated, whatever the matrix says. And the lessons-pinned
  gate itself grew with this entry: its extension list knew only `.py/.sh/.yml`,
  so a lesson amending a port's Rust or C — like this one — was checked by
  nothing (the extension-list twin of the `ports/` prefix gap, LESSONS #19);
  `.rs/.c/.h` are now extracted and enforced, with negative fixtures.
- **Section amended:** ports/cjson/rust/crates/core/src/dom.rs
  (`get_array_size`); ports/cjson/rust/crates/core/src/modes.rs;
  ports/cjson/oracle/cjson_modes.c; harnesses/doc-check/check_lessons_pinned.py
  (extension list + self-test); PLAYBOOK · Phase 4 entry criteria;
  PROMPTS/10-module-port.md · step 0.

---

## 027. A shared driver's new branch corrupted the modes it didn't own

- **Date:** 2026-08-29
- **Codebase:** cJSON port, module 9 (`cJSON_Utils`) — found wiring the
  pointer/patch/merge/sort driver modes
- **What happened:** The differential driver is ONE binary dispatching every
  mode. The new cJSON_Utils block split stdin on the first newline and wrote
  `*nl = '\0'` to NUL-terminate the first field — but it did so *before*
  checking whether the mode was actually a utils mode, and only the `sort`
  branch restored the byte. So for every FALL-THROUGH mode
  (minify/print/roundtrip/dup), any newline-bearing input reached the C library
  truncated at the first newline: `print "a\nb"` made the *oracle* emit `"a"`
  (the string value NUL-terminated mid-buffer) while the correct Rust emitted
  `"a\nb"`. The oracle — the thing the port is measured against — was now wrong,
  and the port "diverged" by being *right*. The matrix differential never caught
  it (its vectors are newline-free compact JSON); nothing in the utils gates
  could see it (utils modes behaved correctly). It surfaced only when the
  PRE-EXISTING base modes were re-fuzzed after the shared driver changed: minify
  found 25 divergences, the first at iteration 1. This is the LESSONS #26 shape
  inverted — there a gate was blind to a NEW surface; here the newly-broken
  surface was the OLD modes, corrupted by a new sibling mutating shared state
  they depend on.
- **Kit change:** `driver.c` computes `is_utils` from the mode name BEFORE
  touching `input`, and only the utils branch splits — the fall-through modes
  always see pristine bytes; a revert re-fails the base-mode diff-fuzz. Wired
  into the prompt: after any change to the SHARED differential driver, re-run the
  diff-fuzz of the PRE-EXISTING modes, not just the new one — a shared harness is
  software whose new branch can break the old callers (the "test harness is
  software with a hostile host" habit, extended from encoding/quoting to
  cross-mode buffer state).
- **Section amended:** ports/cjson/oracle/driver.c (`is_utils`-before-mutate);
  PROMPTS/10-module-port.md · step 0 (shared-driver re-fuzz).

## 028. A predicate-defined intentional divergence can't be pinned — fuzz against a corrected oracle

- **Date:** 2026-08-29
- **Codebase:** cJSON port, module 9 (`cJSON_Utils`), JSON Patch
- **What happened:** The port intentionally FIXES a cJSON defect —
  `decode_pointer_inplace` writes `decoded_string[1] = '/'` where `[0]` is meant,
  so a Patch child key `a~1b` builds `a~/` instead of `a/b` (ledgered
  `utils-tilde-*`, CWE-707). The matrix differential handles that with three
  pinned rows. But differential FUZZING against the pristine oracle rediscovers
  the divergence for EVERY `~`-escaped child key — an unbounded class, not a
  finite set of fingerprints. Each witness looks like a fresh finding; the fuzzer
  is a whack-a-mole that never goes green, because the divergence is
  *predicate-defined* ("any input where a Patch key contains `~0`/`~1`") and a
  predicate has infinitely many witnesses.
- **Kit change:** the **corrected-fuzz-oracle** pattern. `make_fixed_utils.py`
  regenerates `cJSON_Utils.c` with ONLY the one-line decode fix (the pristine
  vendored source is never touched; the generated `.c` and its binary are
  gitignored), and `build_fixed.sh` builds `cjson_oracle_fixed`. `check.sh`
  fuzzes `patch` against THAT: both sides decode correctly, the intentional class
  collapses to no-divergence, and any finding is a REAL port bug — which is
  exactly how this port's invalid-escape decode, array-index terminator, and a
  NUL-key bug were caught. The other five utils modes have no intentional
  divergence and fuzz against pristine C. General rule, wired into the prompt:
  when the port diverges from the oracle by a *predicate* (a fix-of-defect over a
  whole input class), differential fuzzing needs a reference that shares the fix,
  or it cannot tell the intentional class from a real bug.
- **Section amended:** ports/cjson/oracle/make_fixed_utils.py;
  ports/cjson/oracle/build_fixed.sh; ports/cjson/check.sh (module-9 diff-fuzz);
  DIVERGENCES.md (`utils-tilde-*`); PROMPTS/10-module-port.md · step 2.

## 029. C-string (NUL-truncation) semantics must hold at EVERY boundary, not most

- **Date:** 2026-08-29
- **Codebase:** cJSON port, modules 6 (`dom`) + 9 (`cJSON_Utils`)
- **What happened:** cJSON stores keys and strings as C strings — every compare
  (`strcmp`, `case_insensitive_strcmp`, `compare_pointers`, `compare_strings`)
  and every print stops at the first NUL. The base port reproduced this for
  string VALUES (`dom::compare` via `strcmp_eq`) and for PRINTING keys — but
  object-KEY lookup (`get_object_item`) compared FULL bytes. So a key `a\0b` was
  distinct from `a` for lookup/compare yet identical when printed: an internal
  inconsistency, faithful in the visible half and divergent in the half no single
  vector happened to probe. It stayed latent on `main` from the dom module until
  fuzzing put NUL-bearing keys on the compared surface — `dup-eq` on
  `{"a\0":1,"a":2}` said a value equals its duplicate (Rust `true`) while C said
  `false`, and utils merge/genmerge/genpatch diverged wherever a NUL-collapsing
  key appeared. The dedicated `dup-eq` mode COULD have shown it, but the base
  fuzz never generated a NUL-collapsing dup key.
- **Kit change:** NUL-truncation now applies at every key boundary —
  `dom::get_object_item` (case-sensitive via `strcmp_eq`) and `dom::eq_ci`
  (case-insensitive, truncating too), and `utils::key_matches` /
  `utils::compare_keys` — so the port's key semantics ARE the C's C-string
  semantics everywhere, not just at print; pinned by the `dup-eq` differential
  and `utils::tests::keys_compare_nul_truncated`. A sibling defect fell out of
  the same fuzzing: RFC-7396 null-merge calls `cJSON_DeleteItemFromObject`, which
  removes only the FIRST matching key, but the port's `retain` removed ALL —
  corrected to remove-first (`merge_null_removes_only_the_first_duplicate`).
  Rule: when the source treats a datum as a C string, apply the NUL-truncation at
  compare AND lookup AND print, or a single un-truncated boundary is a divergence
  waiting for the one input that reaches it. **A later HIGH-BUDGET fuzz pass
  (25k iters × seeds, vs the gate's 2k) proved the "not most" thesis literally:
  it found THREE more un-truncated boundaries the key fix hadn't reached — a JSON
  Patch op's `op`/`path`/`from` (cJSON's `valuestring`, so `path:"\0"` is the
  root path and `/a/-\0` is `/a/-`), the GetPointer pointer itself (`/a\0/b` is
  the pointer `/a`), and the GENERATED pointer path in genpatch
  (`encode_string_as_pointer` is strlen-based, so a key `a\0` encodes to `a` and
  a nested diff addresses `/a/`, not a NUL-bearing `/a` that drops its tail on
  print). All the same rule, one boundary at a time; each fixed at its single
  chokepoint (`as_string`, the `ptr` branch, `encode_pointer_segment`) and pinned
  (`patch_path_is_nul_truncated`, `pointer_is_nul_truncated`,
  `genpatch_encodes_nul_truncated_key_paths`). The budget, not the technique, was
  the difference — a hardening pass earns its keep.**
- **Section amended:** ports/cjson/rust/crates/core/src/dom.rs (`get_object_item`,
  `eq_ci`); ports/cjson/rust/crates/core/src/utils.rs (`key_matches`,
  `compare_keys`, `merge_patch` delete-first, `as_string` op/path/from,
  the `ptr` pointer, `encode_pointer_segment`).

## 030. A property test encodes an ASSUMPTION — validate it against the oracle, not the spec

- **Date:** 2026-08-29
- **Codebase:** cJSON port, module 9 (`cJSON_Utils`), hardening pass
- **What happened:** Property-based tests are the right tool to check what the
  differential cannot — the differential only asserts Rust == C, never that
  either is *correct*, so invariants like "minify is idempotent" and the RFC
  round-trips (`patch(genpatch(a,b),a) ≈ b`, `merge(genmerge(a,b),a) ≈ b`) add
  real signal. But each property is an ASSUMPTION, and for a *faithful* port the
  invariant that must hold is the C's actual (quirky) behavior, not the spec's
  ideal. Two "obviously true" properties were false:
  (1) **sort idempotence** — `cJSONUtils_SortObject` permutes an ARRAY via a
  NULL-key mergesort, so `sort(sort(arr)) != sort(arr)`; it is idempotent only on
  distinct-key OBJECTS. (2) **RFC-7396 merge round-trip** — cJSON's `genmerge`
  SORTS keys case-insensitively but DIFFS them with a hardcoded case-sensitive
  `strcmp` (cJSON_Utils.c:1423), while `merge` applies case-insensitively, so the
  round-trip is genuinely ill-defined for a mixed-case key set like `{"Z","aa"}`
  — the C doesn't round-trip it either. Both failures were the TEST's bug, not
  the port's; but chasing them is what surfaced the genmerge case quirk (and, in
  the same pass, real port bugs — see #29). A property that bakes in the spec's
  ideal instead of the oracle's behavior fails on the port's faithful quirks and
  cries wolf.
- **Kit change:** the generator restricts each property to the domain where its
  invariant is actually well-defined — sort idempotence to top-level distinct-key
  objects, the merge round-trip to an all-lowercase key pool whose
  case-insensitive order equals its case-sensitive order — with a comment at each
  restriction naming the quirk that forces it. Reconstruction is checked by
  `dom::compare` (order-independent), not byte equality, so a legitimate
  key reordering is not a false failure. Discipline, wired into the prompt: when
  a property fails, first ask whether the C satisfies it — if not, the property
  is wrong (tighten its domain or weaken its claim to the C's real invariant),
  not the port. Faithful quirks the properties now encode are noted in
  DIVERGENCES.md (genmerge's case-sensitive diff under a case-insensitive sort).
- **Section amended:** ports/cjson/rust/crates/core/tests/properties.rs
  (domain restrictions + `dom::compare` reconstruction); PROMPTS/10-module-port.md
  (validate a failing property against the oracle before the port).
