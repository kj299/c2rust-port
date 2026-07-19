# Full code review — Porting Kit (snapshot `9aa5984`)

Reviewed: every harness (`harnesses/`), `skills/` + `check_skills.py`, `skeleton/`
(all three crates, workspace config, lockfile), the CI template, `Makefile`,
`scripts/lift-to-c2rust-port.sh`, and doc↔code consistency across CLAUDE.md,
PLAYBOOK.md, OPERATING-GUIDE.md, README.md, SECURITY-CHECKLIST.md, PROMPTS/, and
the skill cards.

Method: full read of all ~1,650 lines of Python/bash/Rust plus the templates, then
empirical verification of every suspected behavioral bug (marked **[verified]**
below — each was reproduced with a live experiment; `make check-kit` passes clean
before and after, i.e. none of these are caught by the kit's own self-tests).

The kit's stated bar is that its gates are load-bearing safety controls
("non-negotiable, wired into CI"). Findings are therefore ranked by how badly they
undermine a gate, not by classic crash severity.

> **Status:** the six High findings (H1–H6) are **fixed on this branch** —
> `diff_run.py` (TIMEOUT verdict: rust-side/both-side timeouts hard-fail and
> cannot be ledgered; oracle-only timeouts DIVERGE for triage), `golden.py`
> (refuses to store a timed-out oracle as golden; captures/compares exit codes
> via a `<case>.rc` sidecar, with `--ignore-exit` mirroring `diff_run`),
> `scan_c_flaws.py` (real comment masking replaces the `*`-prefix skip — which
> also fixes **M5**, the format pass scanning comments), and
> `porting-ci.template.yml` (fuzz job fails on an empty target list; sanitizers
> job installs `rust-src`). Each behavioral fix landed with a pinned self-test,
> per the kit's fix-forward rule; the reproduction commands below now show the
> failing/refusing behavior.
>
> The **Medium findings are fixed too**: M1 (`progress.py` accepts `--file` on
> either side of the subcommand), M2 (phantom `unchecked-malloc` category
> removed from the docstring, with an honest note on why), M3 (skeleton CLI
> emits RFC-8259 JSON via `json_escape` and exits 1 on a failed stdin read),
> M4 (`make check-kit` phrasing is layout-aware everywhere), M5 (via H4),
> M6 (ledger entries can pin a `[sha256:...]` fingerprint of the accepted
> divergence — pinned entries re-fail when the divergence changes shape, and
> the tool prints the pin to add for unpinned ones), M7 (`run_sanitizers.sh
> all` states that TSan is excluded and errors clearly when `rustc` is
> missing), M8 (CLAUDE.md's gate chain now lists all six). Bonus: the phantom
> `--update-ledger` flag in `diff_run.py`'s usage line (never implemented) was
> removed. Low findings remain open.

---

## High — a safety gate can pass when it should fail

### H1. `diff_run.py`: both sides timing out is reported as `MATCH` **[verified]**
`harnesses/differential/diff_run.py:82-83` turns a timeout into synthetic output
`"<<TIMEOUT>>\n"` with rc 124 — for *both* binaries. When oracle and Rust both hang,
the synthetic outputs and exit codes are equal, so `compare()`
(diff_run.py:101-108) declares `MATCH` and the run exits 0:

```
$ diff_run.py --oracle slow.sh --rust slow.sh --matrix m.json   # both sleep > timeout
[MATCH             ] hang
1 cases, 0 unexplained divergence(s)   → exit 0
```

PLAYBOOK.md:197-199 promises the opposite: "the harness's per-case timeout marks a
wedged run as `<<TIMEOUT>>` **and fails it**." The scenario this hides is exactly
the kit's founding bug (the winlsof hang, LESSONS #1): a port that *faithfully
re-implements a hang* sails through the liveness backstop. **Fix:** treat rc 124 /
the `<<TIMEOUT>>` sentinel as an unconditional failure verdict (e.g. a distinct
`TIMEOUT` verdict that is never `MATCH` and is not ledger-suppressible), and pin it
in `_self_test`.

### H2. `golden.py capture` enshrines a hang as golden truth **[verified]**
`harnesses/golden/golden.py:39-41`: a hanging oracle times out identically on every
repeat, so the runs compare "stable" and `<<TIMEOUT>>` is written as the golden
file, exit 0, no warning:

```
$ golden.py capture --oracle slow.sh --matrix m.json --corpus gcorp --repeats 2
captured 1 golden case(s) into ./gcorp     → exit 0
$ cat gcorp/hang.golden
<<TIMEOUT>>
```

The module's own docstring says its purpose is to "flag when the *oracle itself* is
nondeterministic (so you don't enshrine noise as truth)" — but it enshrines a hang
as truth, and `replay` will then *require* the Rust to hang to pass. **Fix:** in
`capture`, refuse to store a golden whose content is (or contains) the timeout
sentinel; report it like the nondeterministic case.

### H3. `golden.py` drops exit-code fidelity — contradicts LESSONS #4
LESSONS #4 ("Differential fidelity is stdout AND exit code, not stdout alone") is
wired into `diff_run.py:97-102`, but `golden.py` ignores it: `capture` stores only
`D.run_one(...)[0]` (stdout) and `replay` (golden.py:77) compares only stdout. The
golden corpus is precisely the *oracle-substitution* path — used when the C
reference can't run in CI — so on that path the exit-code half of gate 2 silently
disappears, and a golden-replay wrapper can't reproduce the oracle's rc for
`diff_run` either (making `--ignore-exit` mandatory and the lesson unlearned).
**Fix:** store rc alongside stdout (e.g. a first-line header or a sidecar
`<case>.rc`), compare it in `replay`, and teach the wrapper recipe to `exit` with it.

### H4. `scan_c_flaws.py` silently skips real code lines starting with `*` **[verified]**
`harnesses/c-flaw-scan/scan_c_flaws.py:126-127` skips any line whose stripped form
starts with `*` (intended: block-comment continuation lines). That also matches the
common C idiom of pointer-dereference assignment:

```c
*out = malloc(a * b);        /* int-overflow-mul  — NOT reported */
*dst = strcpy(buf, src);     /* unbounded-copy    — NOT reported */
```

Verified: a file containing exactly those lines scans as "0 potential flaw
site(s)". The tool's stated bias is to over-report ("deliberately noisy; every hit
is a question") — silent false *negatives* are the one direction a Phase-0 security
scanner must not err in. **Fix:** strip comments properly (a C variant of
`audit_unsafe.py`'s `_mask`) instead of the `*`-prefix heuristic, and add these two
lines to `SELF_TEST_C`.

### H5. CI template: the fuzz gate passes vacuously when no targets exist
`harnesses/ci/porting-ci.template.yml:83-86`:

```yaml
- run: |
    for t in $(cargo fuzz list 2>/dev/null); do
      cargo fuzz run "$t" -- -max_total_time=60
    done
```

If the repo has no `fuzz/` directory (or `cargo fuzz list` fails — stderr is
discarded and a command-substitution failure doesn't trip `-e` here), the loop body
never runs and the job is green. "No panic on input" is one of the six
non-negotiable gates; this lets it not exist while reporting green. **Fix:**
`targets=$(cargo fuzz list); test -n "$targets"` and fail with a clear message when
empty (or make zero-targets an explicit, documented opt-out).

### H6. CI template: sanitizers job is missing the `rust-src` component
`porting-ci.template.yml:70-73` installs `dtolnay/rust-toolchain@nightly` with no
components, then runs `run_sanitizers.sh asan|ubsan`, which invokes
`cargo +nightly test -Zbuild-std --target $TRIPLE`
(harnesses/sanitizers/run_sanitizers.sh:48-49). `-Zbuild-std` requires the
`rust-src` component; the default (minimal) toolchain doesn't include it, so the
job fails on first real use — and a template gate that always fails gets deleted,
not fixed (a "skipped control is a broken control," per the kit's own
retrospective prompt). The adjacent miri job gets this right
(`with: { components: miri }`). **Fix:** `with: { components: rust-src }`.

---

## Medium — wrong docs, phantom coverage, and design gaps

### M1. `progress.py`: the documented usage is rejected by the CLI **[verified]**
The docstring (harnesses/progress/progress.py:15) shows
`progress.py {init,set,show,ingest} [--file progress.json]`, but `--file` is
defined on the top-level parser only, so it must *precede* the subcommand:

```
$ progress.py set mymod ported --file p.json
error: unrecognized arguments: --file p.json     → exit 2
```

**Fix:** add `--file` to each subparser (a shared parent parser), or fix the
docstring. Given the tracker is meant to be driven by agents pasting commands from
docs, the CLI accepting both orders is the safer fix.

### M2. `scan_c_flaws.py` docstring promises an `unchecked-malloc` category that doesn't exist
scan_c_flaws.py:20 lists `unchecked-malloc … (CWE-690) [weak]` under "Categories
flagged", but `CHECKS` (lines 35-48) and the format-string pass implement no such
check — the category can never fire. A user reading the header believes CWE-690 is
covered; it isn't. (The `porting-kit-cflaw-scan` skill's category list correctly
omits it, confirming the drift is in the module docstring.) **Fix:** implement the
heuristic or delete the line.

### M3. Skeleton CLI emits invalid JSON for control characters **[verified]**
`skeleton/crates/cli/src/main.rs:28-31` builds JSON with Rust's `{:?}` debug
formatting, which escapes control characters Rust-style:

```
$ printf 'c = ctrl\x01byte\n' | port --format json
  {"key": "c", "value": "ctrl\u{1}byte"}      ← \u{1} is not JSON
$ python3 -c "json.load(...)"  → JSONDecodeError: Invalid \uXXXX escape
```

The example input matrix ships a `utf8-and-control-bytes` case aimed at exactly
this input class, and `skeleton/DIVERGENCES.md`'s example entry even advertises
"Rust emits RFC-8259-strict JSON (escaped control chars)" as the port's
improvement over C. The skeleton is the shape modules are copied from — a
template that quietly violates the property the kit brags about will be
replicated. **Fix:** emit real JSON string escaping (backslash-uXXXX escapes for control
characters, plus `"` and `\`), or a `// PLACEHOLDER: not RFC-8259` warning if the simplicity is
deliberate.

Related nit in the same file: `let _ = std::io::stdin().read_to_string(&mut input);`
swallows read errors (e.g. non-UTF-8 stdin), silently proceeding with empty/partial
input and exit 0 — at odds with the kit's exit-code-fidelity lesson. Propagate the
error and exit nonzero.

### M4. `make -C porting-kit check-kit` fails in this repo layout **[verified]**
This repo *is* the kit at the root — there is no `porting-kit/` directory — yet the
command appears as `make -C porting-kit check-kit` in CLAUDE.md:44, PLAYBOOK.md:258,
PROMPTS/00-new-port-kickoff.md:44, skills/README.md:13, and the Integrity footer of
all six SKILL.md files. README.md and OPERATING-GUIDE.md use the correct
`make check-kit`. CLAUDE.md is the file that governs agent sessions in this repo,
and its canonical smoke-test command errors out here. **Fix:** standardize on
"run `make check-kit` from the kit root (vendored ports: `make -C porting-kit
check-kit`)", or keep the vendored phrasing everywhere and add a top-level
passthrough note in this repo.

### M5. The format-string pass scans inside comments **[verified]**
`_scan_format_strings` (scan_c_flaws.py:101-118) runs over the raw source with no
comment stripping, so commented-out code is flagged:

```c
/* old code:
   printf(user_fmt);        ← reported as CWE-134
*/
// fprintf(stderr, dynfmt, x);   ← reported as CWE-134
```

This is inconsistent with the line scanner (which skips comment lines, and whose
self-test asserts "ignores the commented strcpy"). Given this tool's history — 828
false positives once buried the real findings until it was muted (LESSONS #2) —
noise is a first-class defect here, not cosmetic. **Fix:** strip comments once
(shared with H4's fix) before both passes.

### M6. Ledger suppression is by case *name*, forever
`load_ledger`/`compare` (diff_run.py:54-66, 105-106) suppress a divergence if the
case name appears as `- [x] name: …` — with no record of *which* divergence was
accepted. Once `json-format` is ledgered for an intentional C-defect fix, any
*future, unrelated* regression in that case (wrong values, new crash output) also
reports `DIVERGE(ledgered)` and exits 0, indefinitely. The most-exercised cases are
the most likely to be ledgered, so the gate is weakest exactly where behavior
changes most. **Fix:** store a fingerprint of the accepted normalized diff (or
expected-output file) with each ledger entry and fail when the observed divergence
no longer matches it.

### M7. `run_sanitizers.sh all` silently omits TSan
run_sanitizers.sh:61 runs miri + asan + ubsan for `all`; CLAUDE.md's gate table
says "miri/asan/ubsan/tsan" and the kit's origin bug is a *threading* hang. If the
omission is deliberate (TSan is slow / needs threaded tests), `all` should say so
in its output; today a user running `all` reasonably believes the thread class was
covered. Related minor: with no `rustc` on PATH, `TRIPLE` is empty (line 31) and
`run_san` fails with a confusing `--target ""` error.

### M8. CLAUDE.md says "all six" gates, then lists five
CLAUDE.md:30-31: "Every module clears all six before merge:
`ported → differential → fuzzed → sanitized → unsafe-audited`" — five stages. The
sixth (pin-the-regression + merge, per PLAYBOOK Phase 4 step 6 and the module
skill) is missing from the chain in the kit's most normative file, and it's the
gate the retrospective calls out as the one winlsof kept skipping. **Fix:** append
`→ pinned+merged` (or reword to "five tracked gates + pin/merge").

---

## Low — robustness, tests, and polish

- **L1. `audit_unsafe.py` self-test asserts less than its label claims**
  (audit_unsafe.py:275): "undocumented is the block on line 5" only checks
  `undoc[0][1] == "block"`, not the line number. `undoc[0] == (5, "block")` would
  pin it.
- **L2. `diff_run.py` never compares stderr** — `run_one` returns stdout only.
  For CLI tools, error text is behavior (and it's where a C tool's crash spew vs
  Rust's clean error would show). At minimum state the limitation in the
  docstring; ideally add `--with-stderr`.
- **L3. Golden corpus filenames are unsanitized case names**
  (golden.py:41,71): a case named `../x` writes outside the corpus. The kit's own
  lesson is "the test harness is software with a hostile host" — reject path
  separators in case names in `load_matrix`.
- **L4. `golden.py` doesn't record capture-time `--sort`/`--mask-numbers`**, so a
  replay with different flags fails with no hint why. Store them in the corpus
  (e.g. a `corpus.meta` file) and warn on mismatch.
- **L5. `progress.py set` silently creates unknown modules** (progress.py:45-52):
  a typo (`procss`) adds a new row instead of erroring, and the table then
  undercounts real progress. Error unless `--add` is passed.
- **L6. `cmd_ingest` matches module names as substrings of report *filenames***
  (progress.py:96-100): module `io` matches `prio.json`; a whole-workspace report
  advances nothing. It's documented as a heuristic, but exact-stem matching would
  cost one line.
- **L7. `run_supply_chain.sh --check` dies silently if the template is missing**
  (run_supply_chain.sh:18): `test -f … && echo PASS` under `set -e` exits 1 with
  no message. Use an explicit `|| { echo FAIL…; exit 1; }` like
  `gen_fuzz_target.sh` does.
- **L8. The skeleton crate is named `core`**, shadowing the built-in core crate.
  It builds and tests cleanly today (verified with 1.94.1) because `--extern`
  shadows the sysroot and std macro hygiene protects expansions, but it's a
  reserved name on crates.io, confuses readers (`core::parse` looks like libcore),
  and "rename the crates" is exactly the instruction people skip. A neutral
  placeholder (`port_core`) removes the trap.
- **L9. CI `paths:` scoping omits `porting-kit/**`** (porting-ci.template.yml:19-21)
  while three jobs execute `porting-kit/harnesses/...` scripts — a kit update
  (e.g. fixing the audit harness) won't re-run the safety pipeline that depends
  on it.
- **L10. The `utf8-and-control-bytes` example case contains no multibyte UTF-8**
  (input-matrix.example.toml, last case): the comment promises "then multibyte
  UTF-8" but the stdin is pure ASCII — `manana` looks like a mojibake casualty of
  `mañana`. The case name claims coverage the vector doesn't provide.
- **L11. OPERATING-GUIDE §5 backlog item 9 is already (partially) shipped**:
  "`progress.py ingest` to parse harness JSON" exists (progress.py:87-103, and
  §1 of the same guide references it). Mark it partially done — today it ingests
  only unsafe-audit JSON for the final gate.
- **L12. `scanf` regex misses `fscanf`/`sscanf` `%s`** (scan_c_flaws.py:39) —
  same CWE-120 class, two more names in the alternation.

---

## What's solid (verified, not vibes)

- `make check-kit` is green, and every Python harness has a real self-test with
  meaningful fixtures — the both-directions format-string test in
  `scan_c_flaws.py` and the exit-code fixtures in `diff_run.py` clearly encode
  past lessons.
- `audit_unsafe.py`'s `_mask` tokenizer is genuinely careful: nested block
  comments, raw strings with hash guards, byte strings, char-vs-lifetime
  disambiguation, and byte-offset preservation so line numbers stay true. Spot
  checks against tricky inputs held up.
- The skeleton builds and tests clean with the workspace lints wired
  (`[lints] workspace = true` in all three crates), `forbid(unsafe_code)` on
  `core` is real, and the `sys` example's two SAFETY comments state actual
  invariants rather than "this is fine".
- `check_skills.py` does what it promises — all six skills' `porting-kit/<path>`
  references resolve, and the self-test proves both the pass and fail paths.
- `lift-to-c2rust-port.sh` is unusually defensive for a one-shot script
  (source-guard, error-cause triage on `ls-remote`, no-pipeline archive fallback,
  scratch `GIT_CONFIG_GLOBAL`); only nit: the `mktemp` config file is never
  cleaned up.

## Suggested fix order

1. H1 + H2 + H3 (one theme: timeouts and exit codes in the differential/golden
   pair — the two gates the whole kit hangs on), each with a pinned self-test.
2. H4 + M5 (one shared comment-stripping fix in the scanner) + M2 + L12.
3. H5 + H6 + L9 (CI template).
4. M1, M4, M8 (doc/CLI truthfulness — cheap, and they're the paste-able surface
   agents actually execute).
5. M3/M6/M7 and the L-tier as they're touched.

Per the kit's own rule, each fix should land with the regression test that would
have caught it — H1/H2/H4/M1/M3 above come with ready-made reproduction cases.
