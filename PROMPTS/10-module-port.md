# Prompt — port one module (the Phase 4 loop)

Paste this once per module, after Phase 0/1 are agreed. Replace `[MODULE]`.

---

Port the C module **`[MODULE]`** to Rust following `porting-kit/PLAYBOOK.md`
Phase 4. Re-read PLAYBOOK Phase 4 and `RETROSPECTIVE-lsof.md` §6 first.

**If this module was flagged hazardous (blocking syscall, exotic ioctl, unions,
threads), SPIKE FIRST:** a timeboxed experiment on the one scary operation —
does it block? need privilege? vary by platform/version? — and record the result
*before* committing to a design. This single habit is the highest-ROI lesson in
the retrospective.

Then run every gate; each is a hard requirement before merge:

0. **Probe the oracle before you write a line of Rust** (LESSONS #17, mechanized
   by LESSONS #21). Write this module's edge cases — boundaries, malformed input,
   the values its own code special-cases — as a probes file, then:
   `python3 porting-kit/harnesses/probe/probe.py run --probes <probes.json>
   --oracle <c-oracle> --transcript <t.json>` pins the C's observed bytes, and
   `probe.py gen --transcript <t.json> --out <crate>/tests/<module>_probes.rs`
   **generates** the unit-test expectations from them (you supply one
   `tests/probe_glue/mod.rs` mapping driver modes to the crate's API). Do NOT
   write an expectation by hand and do NOT reason from the C source about what it
   "must" do: on the cJSON port that reasoning was wrong every time it mattered
   (a lossy `%1.15g` the C happily accepts; `Compare` rejecting a value's own
   duplicate; minify ignoring escape parity). Wire `probe.py verify` into the
   port's gate script — it fails closed on oracle drift, transcript tampering,
   and hand-edits to the generated file — **and `probe.py coverage --probes
   <files> --progress progress.json`, so a module nobody probed is red rather
   than invisible** (LESSONS #23). Tag each probes file with the `modules: [...]`
   it decides. **Check the driver's modes against the module's PUBLIC API, not
   just its pipeline** (LESSONS #26): the differential judges only the surface
   the driver exposes, and an accessor no mode calls is ungated — probe every
   entry point the module claims, adding driver modes where none can reach it.
   Where a probed behavior looks like a bug, that is a *decision* —
   reproduce it faithfully, or fix it and ledger the divergence — never a silent
   cleanup. **The differential driver is one binary shared by every mode; a new
   mode that mutates the input buffer (splitting, NUL-terminating) can corrupt
   the modes it doesn't own** (LESSONS #27) — decide the dispatch BEFORE touching
   `input`, and after any change to the shared driver re-run the diff-fuzz of the
   PRE-EXISTING modes, not just the new one.

1. **Port** into `core` (pure logic) or a safe wrapper in `sys` (if it touches
   FFI). Translate idioms safely: call-twice-for-size → growing `Vec` + length
   checks; pointer/struct math → slices + `repr(C)` with bounds; unions/flexible
   arrays → audited casts each with a `// SAFETY:`; integer math → checked/
   saturating. No `unwrap`/`expect`/unchecked indexing on untrusted input.
2. **Differential-test** vs the oracle:
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust
   <rust> --matrix <m> --ledger DIVERGENCES.md`. A divergence is a TRIAGE: fix the
   Rust, OR — if the C was wrong — record the intentional fix in `DIVERGENCES.md`
   (`- [x] <case>: <why + CWE>`). Never silently match a C bug. **If the fix
   applies to a whole input CLASS (a predicate: "any ~-escaped Patch key"),
   differential FUZZING against the pristine oracle rediscovers the intentional
   divergence forever — an infinite class has no finite set of fingerprints to
   pin** (LESSONS #28). Build a *corrected oracle* (the vendored C + only that
   one fix, generated and gitignored — never edit the pristine source) and fuzz
   the affected mode against it, so both sides share the fix and any finding is a
   real port bug.
3. **Fuzz** the input surface:
   `bash porting-kit/harnesses/fuzz/gen_fuzz_target.sh [MODULE] --crate <crate>`,
   then `cargo fuzz run [MODULE] -- -max_total_time=60`. Any panic/crash blocks.
   Property tests add signal the differential can't (it only asserts Rust == C,
   never that either is correct) — but a property is an ASSUMPTION, and when one
   fails, first ask whether the C satisfies it: a faithful port must uphold the
   oracle's real (quirky) invariant, not the spec's ideal, so restrict the
   property's domain to where the C actually holds it rather than "fixing" the
   port (LESSONS #30).
   **The gate's iteration count is a regression FLOOR, not proof of sufficiency**
   (LESSONS #33). A fixed budget is what keeps CI cheap; it is not what makes a
   module done. cJSON module 9 was declared DONE with six green gates and the next
   two commits fixed four real divergences, none reachable at the gate's 2000
   iterations and all found at 25 000 across two seeds. So before calling a module
   DONE: run a **high-budget sweep — ≥10× the gate budget, ≥2 seeds, every mode —
   with zero findings**, and argue the budget from the module's actual input space
   (modes × framing × grammars) instead of inheriting the previous module's
   number. A module whose surface is many times larger than its neighbour's must
   not get the same effort by default.
4. **Sanitize:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh miri .`
   (and `asan`/`lsan`/`tsan` for the `sys` layer / threaded code — `lsan` catches
   FFI-boundary leaks; `tsan` only earns its cost with real threads).
5. **Unsafe-audit:** `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py
   crates/` — must report **0 undocumented**. Add a `// SAFETY:` to any block it
   flags.
6. **Pin the oracle case + merge.** If a bug slipped through, add the golden/
   matrix case that would have caught it *in the same change* (the retrospective's
   "fix-forward, then immediately pin" rule — winlsof often shipped the fix first
   and the test late).

Advance the tracker as gates clear:
`python3 porting-kit/harnesses/progress/progress.py set [MODULE] <gate>`.

Report the module's final gate row and any new `DIVERGENCES.md` entries.
