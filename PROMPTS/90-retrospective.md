# Prompt — end-of-port retrospective (patch the kit)

Paste this when a port (or a major phase) is done. This is what makes the kit
**compound**: every port leaves it sharper than it found it.

---

The `[PROJECT]` port (or phase `[PHASE]`) is complete. Run the closing
retrospective and **patch the Porting Kit** with what you learned.

0. **Run every harness against the real target and record what each finds.** This
   is not optional and not last: the kit's three post-ship dry-runs (LESSONS
   #2–#4) each found a defect *in a harness* — a scanner too noisy to trust, a
   gate delegated to an unwired lint, a differential that judged less than it
   captured — and *none* surfaced from reading the playbook. A dry-run that
   doesn't execute the tools against the actual codebase is theater. Run
   `scan_c_flaws.py`, `audit_unsafe.py`, the differential, etc. against this
   project and eyeball the signal-to-noise before trusting any of it.
   **Probe each gate's fail-closed behavior too** (LESSONS #6): feed it the
   degenerate case — no targets, a hung binary on both sides, a missing
   component — and confirm it goes red. A gate that passes when nothing ran is
   the failure class reading can't find and green CI actively hides.
   **And re-verify every inherited "this doesn't work here" claim before you
   repeat it** (LESSONS #15): a negative environment finding — Actions is blocked,
   that tool isn't installed, the API is unavailable — is the fact most likely to
   be carried across sessions and least likely to be re-tested, because retesting
   feels redundant. The v1.x audit published "CI has never executed" hours before
   its own PR went green in CI. No gate watches prose: re-run the thing, and write
   environment claims **dated and scoped** ("as of YYYY-MM-DD, in this repo").
   When one turns out stale, correct it with a dated note — never a silent rewrite,
   which erases the failure mode instead of recording it.
   **And never bake a conclusion into a recurring prompt** (LESSONS #32): when you
   schedule a check-in, hand off, or write a task for future-you, carry the
   **re-test command**, not the verdict — "run X and report the result", never
   "X is broken; confirm nothing changed". The cJSON watch wrote "Actions is
   disabled at the account level" into its own check-in prompt and then re-read it
   as an established premise ~6 times over two days without retesting; one API
   re-run (accepted, `201`, jobs rescheduled) disproved the mechanism instantly.
   A conclusion in a recurring prompt is a premise you will never re-derive, and
   it launders itself into your reports. Date every environment claim by when it
   was last **executed**, not last asserted — and if you find yourself declining a
   cheap experiment because it "would only re-confirm", that is the experiment to
   run.

1. **Reconstruct the experience from artifacts**, the way
   `RETROSPECTIVE-lsof.md` was built — lean on git history, especially:
   - commit *sequences* where a message says "the real fix" / "actually" (these
     mark where the first approach failed — highest signal, more than reverts),
   - churn per file/module (proxy for time sinks),
   - the `progress.json` final state and the `DIVERGENCES.md` entries.

2. **Diff lived experience against `PLAYBOOK.md`.** For each phase ask:
   - Did the entry/exit criteria match reality? Was a gate missing that would
     have caught a bug earlier?
   - Did any harness misfire, over-report, or miss its target? Did any produce
     enough friction that it got skipped (a skipped control is a broken control)?
   - Did a failure occur that the playbook, as written, would NOT have prevented?
     That is the most important finding.

3. **Patch the kit** — make the concrete edits, don't just describe them:
   - amend `PLAYBOOK.md` phases/criteria,
   - fix/extend a harness (add the normalization rule, the flaw pattern, the
     gate) and re-run the kit's `make check-kit`,
   - update `ARCHITECTURE-TEMPLATE.md` / prompts if the shape or loop changed,
   - **review every NEW or changed kit artifact against the LESSONS list**
     (LESSONS #13): each entry is a checklist item, not history — the v1.0 exit
     test shipped violating two already-logged lessons (fail-open + unpinned
     ledger) because nothing forced the list against new code,
   - **pin each new lesson in the smoke tests**: a lesson whose `Section
     amended` names a harness must land with the regression check in that
     harness's self-test and a `LESSONS #N` citation beside it — `make
     check-kit` (`check_lessons_pinned.py`) hard-fails an unpinned lesson, in
     this repo and in every port's vendored kit.

4. **Append to `LESSONS.md`** — one entry per lesson, in the required format
   (date, codebase, lesson, playbook section amended). If the kit already had
   the lesson but it didn't fire, say why (friction? unclear? not wired to CI?).

4b. **Send every harness fix the port forced back to the kit, in this session**
   (LESSONS #20). A harness meets its real bugs only on a real port: `lib_diff`
   had a full self-test suite, survived the gate-mutation sweep, and still crashed
   the first time a foreign port passed it a bytes-valued return through `--json`.
   Coverage of a gate's *decision* is not coverage of the plumbing around it. If
   the port worked around a harness rather than fixing it, that workaround is the
   bug report — fix the harness and pin it.

4c. **Diff every shared harness against every copy of this kit that a port
   vendors** (LESSONS #45). 4b assumes the port and the kit are one repository.
   They are not: a port vendors a COPY at `porting-kit/`, the fixes it forces land
   in that copy, and this kit — the one the NEXT port copies — never hears of
   them. At the lsof cutover three of the four fail-opens a probe of this kit
   found had been fixed in the lsof copy already, one of them months earlier.
   With both trees checked out:

       for f in $(cd porting-kit && find harnesses skills -name '*.py' -o -name '*.sh'); do
         cmp -s "porting-kit/$f" "$KIT/$f" || echo "$f"; done

   Most differences are renumbered `LESSONS #N` citations — the logs diverge, so
   that is expected. For each that is not, decide: **a fix the copy has** (bring
   it here), **a fix this kit has** (send it there), or a deliberate divergence
   (say so in the copy's README). Bringing one here is an import in the *other*
   direction: the copy's history is its own, and a `LESSONS #N` carried over
   verbatim still resolves here and means a different lesson. Name its entries
   as "the lsof line's entry NNN", never as a citation.

   Then probe what you brought back **against this kit's structure, not the
   copy's** — and probe the copy too before saying anything about it. The
   literal-blanking fix would have silenced `scanf("%s")` here, and LESSONS #45
   recorded that the copy it came from was safe; it had been silencing the same
   check there since the day it landed (LESSONS #47). A claim about the other
   tree is a run you owe in the other tree.

5. **Commit the kit changes separately** from the port, with a message explaining
   which failure each edit prevents next time.

Report: the top 3 kit improvements you made and the single failure that, in
hindsight, the kit still would not have prevented (the next port's target).
