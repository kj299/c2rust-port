---
name: porting-kit-module
description: Port one C module to Rust through the six safety gates. Use when translating/porting a specific module, function, or subsystem from C to Rust as part of a Porting-Kit port. Runs the per-module loop — spike-if-hazardous, port, differential-test, fuzz, sanitize, unsafe-audit, pin+merge — with each gate a hard requirement.
---

# Porting Kit — port one module (the Phase 4 loop)

Wraps `porting-kit/PROMPTS/10-module-port.md` and PLAYBOOK Phase 4. Re-read those first.

## Spike first if the module is hazardous
If flagged in Phase 1 (blocking syscall, exotic ioctl, unions, threads), run a
timeboxed spike on the one scary operation — does it block? need privilege? vary by
version? — and record the result *before* committing to a design. This is the
highest-ROI habit in the retrospective (the winlsof `NtQueryObject` hang cost 7
commits reactively vs ~1 day up front). For a capability that might be *impossible*
(not just hard), use the research spike-and-gate ritual: rate effort/confidence,
write the decision gate before coding, and do a pivot check before declaring it dead.

**Write it from `skeleton/SPIKE.md`, and label every hazard `ran:` or `read`**
(LESSONS #38). A spike that says "executed, not inferred" and then reasons its way
through the small hazards lends the executed claims' credibility to the read ones,
and nobody — including you, three sessions later — can tell which is which. The
cJSON mutation spike did exactly that: it *ran* `DetachItemViaPointer` and found a
NULL-write, and it *read* `cJSON_SetValuestring`, checked the destination buffer
was long enough, called it "memory-safe as written", and missed that the source
may alias the destination (ASan `strcpy-param-overlap`, ten lines of C to show).
Rule: a `read` row you are about to call **benign** must name the case you did not
try — and if you can name it, run it. Commit every reproducer under the port's
`spikes/` so the claim outlives the session (LESSONS #32).

## Probe the oracle before writing any Rust (step 0)
The C is a spec only the oracle can read (LESSONS #17, mechanized by #21): pin the
module's edge cases with `python3 porting-kit/harnesses/probe/probe.py run --probes
<probes.json> --oracle <c-oracle> --transcript <t.json>`, then `probe.py gen` to
**generate** the Rust test expectations from the C's observed bytes — never write
one by hand. Wire `probe.py verify` into the port's gate script: it fails closed on
oracle drift, transcript tampering, and hand-edits to the generated file — and
`probe.py coverage --probes <files> --progress progress.json`, which fails when a
module has no probes file at all (LESSONS #23; tag each probes file with the
`modules: [...]` it decides). `ports/cjson/check.sh` step 1b is the worked
reference.

## The six gates (each a hard requirement before merge)
1. **Port** into `core` (pure logic) or a safe wrapper in `sys` (if it touches FFI).
   Idiom map: call-twice-for-size → growing `Vec` + length checks; pointer/struct math
   → slices + `repr(C)` with bounds; unions/flexible-arrays → audited casts each with
   `// SAFETY:`; integer math → `checked_*`/`saturating_*` (guard signedness/width,
   overflow, shift/rotation exactly). No `unwrap`/`expect`/unchecked index on input.
2. **Differential-test** vs the oracle:
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust <rust> --matrix <m> --ledger DIVERGENCES.md`
   A divergence is a *triage*: fix the Rust, OR record an intentional fix-of-C-defect
   in `DIVERGENCES.md`. Verdict = stdout AND exit code; a timeout = a design smell
   (design the blocking call out, don't wrap it).

   **Ask what state the C keeps that no output depends on** before designing the
   mode (LESSONS #39): a last-item cache, a length beside a pointer, a memoized
   count, a free list, a dirty flag. A value-comparing differential never reads
   any of it. cJSON's `parent->child->prev` is a last-item cache — a detach
   rewrites it, nothing printable depends on it, and only an *append* reads it
   back, so the `seq` mode carries an append op for no other reason. Name the
   operation that consumes each such field and put it in the mode; if the mode is
   multi-step, emit the descriptor after **every** step, since a corruption at
   step 2 that step 5 masks is invisible to a final-state comparison.
3. **Fuzz** the input surface:
   `bash porting-kit/harnesses/fuzz/gen_fuzz_target.sh <module> --crate <crate>`
   then `cargo fuzz run <module> -- -max_total_time=60`. Any panic/crash blocks.
4. **Sanitize:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh miri .`
   (plus `asan`/`tsan` for the `sys` layer / threaded code).
5. **Unsafe-audit** (must report 0 undocumented):
   `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py crates/`
   Clippy's `missing_safety_doc` + `undocumented_unsafe_blocks` (wired via
   `[workspace.lints]` and CI) cover `unsafe fn` docs.
6. **Pin the regression + merge.** If a bug slipped through, add the golden/matrix case
   that would have caught it *in the same change* (fix-forward, then immediately pin).
   A matrix case gives stdin as `stdin` (UTF-8 text) **or `stdin_b64` (raw
   bytes)** — use the latter for anything a JSON/TOML string cannot spell, such
   as a fuzz reproducer containing a lone 0x80–0xFF byte (LESSONS #36).

Triaging a divergence, before you touch the Rust: ask whether the C's answer is
*defined*. Undefined behavior (a NaN cast to `int`, signed overflow, an OOB read)
has no answer to match, so matching the platform you happen to be testing on
writes UB into the port — take the defined answer and ledger the divergence. If
the class is predicate-defined (*every* NaN, *every* escaped key) it cannot be
fingerprint-pinned for the fuzzer: build a corrected reference oracle for that
mode (LESSONS #28) and keep the finite assertion in the matrix.

Advance the tracker as gates clear:
`python3 porting-kit/harnesses/progress/progress.py set <module> <gate>`
(gates: ported → differential → fuzzed → sanitized → unsafe_audited). Or let the
harness reports drive it — write each `--json` report as `<module>.json` and run
`progress.py ingest --diff-json <m>.json --fuzz-json <m>.json --unsafe-json <m>.json`
to auto-advance a module from its clean reports (exact-stem, fail-closed).

For the hardest modules, consider **two candidate translations by different methods**
and let the vector suite pick the winner (diversity beats any single method).

## Integrity
Commands/paths/gate-names must match the kit and PLAYBOOK Phase 4. Fix the reference on
drift; re-run the kit's `make check-kit` (`make -C porting-kit check-kit` when vendored).
