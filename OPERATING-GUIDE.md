# Operating Guide — running a port with this kit efficiently, securely, well

Recommendations for actually *using* the Porting Kit on a real rewrite: how to
spend tokens and compute wisely, how to harden beyond the baseline, how and when
to reach for each skill, and an honest backlog of what to improve before this is a
v1.0 you'd stake a migration on. Read after `PLAYBOOK.md`.

---

## 0. Readiness assessment (candid)

**Solid today** — proven on a real completed port and self-tested:
the phased playbook; the executable harnesses (`make check-kit` green); the
`forbid(unsafe_code)` core / audited `sys` split; the differential + divergence
ledger; the unsafe-audit hard gate; the compounding LESSONS loop; the skills suite
with a mechanical integrity check.

**Now wired and self-tested** — what this section once called provisional has
landed: the **library** path has two function-level differentials (`cando`
driver-based + `lib_diff` ctypes, complementary); the **performance** gate is a
harness (`perf/perf_gate.py`); C→C **preconditioning** is an invokable skill; and
**held-back vectors + C-baseline validation** are in `golden.py`. The whole §5
backlog is done, and the v1.0 exit test — a real adler32 C→Rust library port driven
through every gate (`examples/adler32/`) — passes.

**Bottom line:** the kit now drives an executable **or** a C-ABI library port
end-to-end through the six gates + a performance gate, substantiates its
safety/security claims (SBOM, signing, differential fuzzing), and has been shaken
out on a real port. The remaining maturity is *breadth* — more real ports feeding
the compounding LESSONS loop — not a missing spine.

---

## 1. Token-use optimization (agent-driven ports)

The kit is designed so an agent reads *verdicts, not corpora*. Lean into that:

- **The harnesses are your token firewall.** Never read a C tree or a diff into
  context to "check" it — run the tool and read its summary. Use the machine
  outputs: `audit_unsafe.py --json --quiet`, `scan_c_flaws.py --json`,
  `diff_run.py --json`. `diff_run` only emits a diff for a DIVERGE case, so a
  green run costs a line, not a file.
- **Delegate reads to subagents; keep the conclusion.** Mapping a module,
  inventorying globals, reading a subsystem → spawn a subagent that returns a
  structured summary (the map), not the files. The orchestrator holds
  `progress.json` + the maps, never the source.
- **Scope context per definition** (also a *correctness* rule — TRACTOR: big-bang
  translation scored worst). Feed the module loop one definition + its
  already-translated deps, never the whole project. Smaller context = fewer tokens
  *and* fewer hallucinated cross-references.
- **`progress.json` is the session anchor.** A resumed session reads the tracker
  (tiny) to orient in seconds instead of re-deriving state from the codebase.
- **Cap the repair loop.** Bounded LLM fix iterations (TRACTOR's practice) — an
  uncapped compile→fix→compile loop burns tokens on diminishing returns; 3–5
  iterations then escalate to a human/spike.
- **Batch independent tool calls** in one turn; don't re-read a file you just
  edited (state is tracked); prefer `--quiet`/`--json` for agent eyes and the
  human tables only when reporting to the user.
- **Two-candidate translation is selective**, not default — spend the extra tokens
  only on the hardest modules where the vector suite picks a winner.

## 2. Efficiency considerations (compute, CI, wall-clock)

- **Path-scope every workflow** (LESSONS #5) so a change runs only the pipeline it
  can affect. The single biggest CI-waste fix.
- **Tier the slow gates:** fuzz = 60s smoke per target in CI, deep run nightly;
  Miri/ASan/UBSan on the `sys`/changed crates per-PR, full sweep nightly. Don't pay
  the whole safety matrix on every push.
- **Leaf-first order is an efficiency lever, not just correctness** — it localizes
  every failure to one definition, so you debug one thing, not a 10k-line blast
  radius. Fewer wasted cycles.
- **Differential per-unit, not just at the end** — catching drift at the module
  that caused it is far cheaper than bisecting it later.
- **`core` builds/tests on the cheap default runner** (no target setup) → fastest
  feedback loop; keep the logic there.
- **Pin + vendor deps** so a clean-machine build never becomes a re-debug session.
- **Spike hazardous modules first** — the winlsof hang cost 7 reactive commits vs
  ~1 day up front. The most expensive inefficiency in the whole retrospective.

## 3. Security hardening (beyond `SECURITY-CHECKLIST.md`)

The checklist is the floor. To make this a *security* rewrite you'd defend:

- **Vet dependency code, not just advisories.** Add `cargo vet` (or `cargo crev`)
  on top of `cargo audit`/`cargo deny` — provenance/review of the actual crates,
  not only known-CVE and license gates.
- **Pin GitHub Actions by commit SHA, not tag** (`uses: actions/checkout@<sha>`),
  set minimal `permissions:` (the template uses `contents: read` — keep it), and
  `persist-credentials: false`. A tag is mutable supply chain.
- **Ship an SBOM + auditable binary:** `cargo auditable build` embeds the
  dependency graph in the binary; `cargo cyclonedx` emits an SBOM. Consumers can
  then scan what you shipped.
- **Sign releases** (cosign / minisign) in addition to the SHA-256 checksum.
- **Fuzz with the sanitizer on** (cargo-fuzz runs ASan by default) and **fuzz the
  threat-model's untrusted boundaries first**. Use `arbitrary` for typed fuzzing of
  structured parsers, and **cap allocations derived from untrusted length fields**
  (integer-overflow-before-alloc is a top C class you must not re-port).
- **Differential fuzzing** (`harnesses/diff-fuzz/diff_fuzz.py`, or the
  `porting-kit-diff-fuzz` skill): feed the *same* mutated input to the C oracle and
  the Rust and compare — finds semantic divergences the fixed matrix never covers.
  The highest-value single addition for a security-critical port; run a short
  budget per PR and a long `--max-time` sweep nightly, seeded from the fuzz corpus.
- **Stricter unsafe lints:** beyond `undocumented_unsafe_blocks` / `missing_safety_doc`
  (wired), consider `clippy::multiple_unsafe_ops_per_block` (isolate each unsafe op),
  `clippy::transmute_ptr_to_ptr`, `clippy::as_conversions` in the `sys` crate.
- **Miri strictness at the FFI seam:** run Miri with strict provenance and the
  alignment checks on the `sys` crate.
- **Secret hygiene as a gate:** run `gitleaks` in CI; assert no tokens/keys land in
  the binary, logs, or committed artifacts.

## 4. Leveraging the skills — strategy (per-skill reference: `skills/README.md`)

The skills are the operational surface; use them, don't re-derive their steps.

**When, across a rewrite** (map the skill to the phase):

| Phase | Skill | Cadence |
|---|---|---|
| Project start | `porting-kit-kickoff` | once |
| Phase 0 vuln hunt | `porting-kit-cflaw-scan` | once (re-run per subsystem) |
| Phase 2 oracle | `porting-kit-oracle` | once, before any Rust |
| Phase 4 per module | `porting-kit-module` | **repeated — the hot path** |
| Phase 4 after matrix green | `porting-kit-diff-fuzz` | per module + nightly sweep |
| Pre-merge / "is it safe?" | `porting-kit-audit` | per module + per release |
| Port/phase done | `porting-kit-retrospective` | once per phase — **never skip** |

**How, efficiently:**
- `cflaw-scan` and `oracle` are independent → run in parallel.
- `module` is the loop you spend the port in; drive it per leaf in topological
  order, delegating the C-reading to a subagent and keeping the translation +
  gate results.
- `audit` is cheap (runs tools, reads verdicts) — gate every merge with it.
- `retrospective` is what makes the kit compound; it patches the playbook, the
  harnesses, **and the skills** (integrity), then appends LESSONS.

**The one-line recipe:** `kickoff → (cflaw-scan ∥ oracle) → for each leaf: module →
audit → retrospective`.

## 5. Improvements backlog (the path to v1.0, prioritized)

**P0 — needed before a *library* port or a security-critical claim:**
1. ~~**`cando`-style function-level differential harness** for C-ABI libraries.~~
   **Done:** `harnesses/cando/cando_diff.py` (+ `driver.template.c/.rs`,
   `vectors.example.toml`) — drives a C-linked and a Rust-linked function driver
   over a vector suite and diffs via `diff_run.compare_one` (shared fidelity). The
   library analog of `diff_run` for executables.
2. ~~**Performance gate harness** — module runtime vs the C median, fail >1.3×.~~
   **Done:** `harnesses/perf/perf_gate.py` — median-of-repeats wall-clock ratio,
   `--threshold` (default 1.3), timeouts fail, spawn-dominated cases reported
   UNMEASURABLE rather than falsely passed.
3. ~~**Held-back vectors + C-baseline validation.**~~ **Done:** baseline validation
   in `cando_diff.py` (a vector the C driver rejects is a BADVECTOR) and in
   `golden.py capture --validate`; and the **holdout** mode landed —
   `golden.py capture --holdout <set>` reserves an acceptance set that `replay` runs
   only under `--final` (a leaked held-out case hard-fails iteration), so the rewrite
   can't be tuned to the visible vectors. (A complementary ctypes, no-driver library
   differential also landed: `harnesses/library-differential/lib_diff.py`, alongside
   cando.)

**P1 — materially stronger:**
4. ~~**Differential fuzzing** harness (C vs Rust on shared fuzz inputs).~~ **Done:**
   `harnesses/diff-fuzz/diff_fuzz.py` — feeds the same mutated input to both binaries,
   judges via `diff_run.compare_one` (so timeout/exit/fingerprint fidelity is shared,
   not copied), minimizes each divergence to its smallest reproducer, and suppresses
   ledger-pinned fingerprints. Runs `--iterations`/`--max-time` budgets;
   `porting-kit-diff-fuzz` skill wraps it.
5. ~~**CI template hardening.**~~ **Done:** every `uses:` SHA-pinned +
   `persist-credentials: false`; a nightly `schedule:` deep tier (fuzz/diff-fuzz)
   over a per-PR smoke; and `cargo-vet`, SBOM (`cargo auditable`/CycloneDX), and
   `gitleaks` jobs alongside audit/deny — in `harnesses/ci/porting-ci.template.yml`.
   **Portability caveat (LESSONS #10):** the template's third-party actions
   (dtolnay/rust-toolchain, …) fail the whole run at startup under a first-party-only
   Actions policy — verify it actually runs in the target repo, and keep the
   `actions/checkout` + preinstalled-toolchain fallback
   (`.github/workflows/check-kit.yml`) for policy-restricted repos.
6. ~~**`scan_c_flaws.py` depth.**~~ **Done:** added `strncpy-noterm`,
   `snprintf-truncation`, and windowed-lexical `use-after-free`/`double-free`/
   `uninitialized-read` heuristics, and made the sink checks whole-file so a
   split-across-lines call isn't missed. Format-string signal (LESSONS #2) preserved.
7. ~~**A `porting-kit-precondition` skill** for Step 0 (C→C).~~ **Done:**
   `skills/porting-kit-precondition` — localize globals into a threaded context
   struct, reduce aliasing, settle the `#ifdef` story, each verified on the C test
   suite before translating.

**P2 — polish / breadth:**
8. ~~`normalize.py` rules as a per-project data file.~~ **Done:** `normalize.py
   --rules <file>` loads rules from JSON/TOML and replaces the built-in defaults;
   `normalize.py --dump-default-rules` emits them to start from; threaded through
   `diff_run.py --rules`.
9. ~~`progress.py ingest`~~ **Done:** `progress.py ingest --diff-json`/`--lib-json`
   (diff_run/lib_diff clean) advance `differential`, `--fuzz-json` (diff_fuzz)
   advances `fuzzed`, `--unsafe-json` advances `unsafe_audited` — exact-stem,
   fail-closed, climbing multiple gates in one call.
10. ~~Document the Windows/cross-platform caveats.~~ **Done:**
    `CROSS-PLATFORM-CAVEATS.md` — sanitizer/Miri availability by toolchain, the
    exit-hard liveness pattern, ASCII-default output, `target/` sync/AV locks, and
    fork-based-harness caveats; referenced from README + PLAYBOOK Phase 3.
11. ~~A `porting-kit-diff-fuzz` skill once #4 lands.~~ **Done** — `skills/porting-kit-diff-fuzz`.

**The v1.0 exit test (the epic's definition of done):** drive a real tiny C-ABI
library end-to-end through every gate. **Done** — `examples/adler32/` (`run.sh`): a
naive-overflow C adler32 vs a correct+safe Rust cdylib, driven through scan →
unsafe-audit → cando → lib_diff → golden (holdout+validate) → diff_run → perf →
diff-fuzz → progress; the overflow is caught by both library differentials and
ledgered as an intentional fix-of-C-defect. The §5 backlog and the exit test are
both complete.

**How the kit closes these:** each is a candidate for a normal port's
`porting-kit-retrospective` pass (the compounding loop is the delivery mechanism —
a real port will surface which of these actually bite first, and LESSONS will
record it). Nothing here is a redesign; all are additive to the proven spine.

---

*This guide is itself subject to the compounding rule: when a port teaches a better
way to spend tokens, compute, or risk, update it and log the lesson in `LESSONS.md`.*
