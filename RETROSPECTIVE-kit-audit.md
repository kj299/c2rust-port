# RETROSPECTIVE — the comprehensive kit audit (v1.0 → v1.x)

A maximal-depth audit of the Porting Kit against its own prime directive — *the
Rust must be safer than the C, and the kit is a compounding asset or it is dead
weight*. Companion to `RETROSPECTIVE-kit-v1.md` (which chronicled the kit
reaching v1.0). This one does not chronicle; it **probes**, and it patches what
the probe found. Every claim below was verified by running the tools or reading
the code in this pass — nothing is asserted from memory.

Scope: `harnesses/` (15), `skills/` (8), `skeleton/`, `examples/adler32`, the
docs, and the compounding loop itself. Method: six adversarial lenses run in
parallel, each told to assume the kit is lying about its own safety and to prove
it by execution, not by reading.

## 0. Step 0 was executed, and it is what found everything

`make check-kit` is green (22 gates — see §4 for why the v1 doc's "14" is now
stale), and `examples/adler32/run.sh` drives a real buggy-C library through every
gate. The finding that matters most in this whole document came not from reading
any harness but from **reverting the port's one real fix and watching the gates
stay green.** The kit's oldest meta-lesson — "a dry-run that doesn't run the
tools is theater" — held again: reading found polish; execution found the hole.

## 1. The six lenses

1. **Live-exercise** — run every harness on adversarial input and on its own
   degenerate cases (empty matrix, reverted fix, invalid-UTF-8 output, high
   bytes). *Found the crown hole (§2) and most of the fail-open cluster (§3).*
2. **Fail-open / fail-closed** — audit every gate for the LESSONS #6 pattern (a
   gate that finds nothing to check must FAIL, not pass). *Found the empty-matrix
   and wrapped-path skips.*
3. **C-flaw-scanner completeness** — does the Phase-0 scanner actually see the
   marquee CWEs, or does it report "0 flaws" on vulnerable C? *Found the missing
   `memcpy`/`memmove`, pre-computed overflow, and cross-brace UAF gaps.*
4. **Harness-as-hostile-software** — the byte-fidelity and quoting lens: does the
   differential preserve bytes, or does decoding launder a real divergence into a
   MATCH? *Found the `decode(replace)`→U+FFFD collapse and the fuzzer's byte
   round-trip.*
5. **Docs / integrity drift** — do the docs, skills, and lesson-pins still match
   the code? *Found the stale gate count, the orphaned review, the skill-list
   omissions, the ledger-name colon truncation.*
6. **Process / loop meta** — is the compounding loop actually compounding, or is
   it a closed circuit? *Produced the honest verdict in §5.*

## 2. The crown finding — the ledger asserted a divergence it never checked for

The deepest hole in the kit sat inside its flagship safety demonstration.

A **ledger entry** (`DIVERGENCES.md`: `- [x] <case> [sha256:..]: why`) is how the
kit says *"this case intentionally differs from C, because we fixed a C bug — do
not treat the difference as a regression."* It is the mechanism that lets a port
be *safer* than the C rather than bug-for-bug identical. But `compare_one`
evaluated `MATCH` **before** it consulted the ledger, so a ledgered case that
*stopped diverging* was silently downgraded to `MATCH` and passed.

Concretely: `examples/adler32` exists to prove the kit catches a real C defect —
a `uint32` checksum overflow that the Rust port refuses. Rewrite the Rust fix as
`wrapping_add` (byte-identical to the C — exactly what a developer "just matching
C" would write, re-introducing the vulnerability), and the flagship exit test
went **green, printed its full success banner, and exited 0**, in *both* library
differentials. The port's entire reason to exist could be deleted and every gate
stayed green. A ledger that only *suppresses* a divergence, without *asserting it
still occurs*, rots into a blind spot: accepting a thing had become not-looking-
at it.

**Fixed** (this pass): a ledgered case that now MATCHes is a new **`LEDGER-STALE`**
verdict — a hard failure that never passes and can never itself be ledgered — in
the shared `compare_one` (diff_run + cando + diff-fuzz) *and independently* in
`lib_diff`'s separate `compare_call`. Pinned in three self-tests and proven
end-to-end: reverting the adler32 fix now fails the exit test (exit 1, no banner,
`LEDGER-STALE`) where it previously passed green. Recorded as **LESSONS #14** —
"an allow-list must ASSERT the accepted state, not merely SUPPRESS it" —
generalizing beyond ledgers to every suppressed lint, ignored advisory, and
expected-failure test in the kit.

This is distinct from LESSONS #8 (which pins a divergence that *mutated*): the
fingerprint pin never fires on a *vanished* divergence, because there is nothing
left to fingerprint. Two different failure modes of the same allow-list; the kit
now covers both.

## 3. The fail-open cluster (all fixed, all LESSONS #6 recurrences)

The live-exercise and byte-fidelity lenses turned up six more gates that could
report success while checking nothing. Each was fixed with a pinned self-test in
the same change, and each is a recurrence of the already-logged LESSONS #6
("gates fail closed") — logged in place under #14, not minted as new lessons:

| # | The fail-open | The fix |
|---|---|---|
| 1 | An empty or mis-keyed matrix/vector suite made every differential exit 0 over a *wrong or absent* binary. | `load_matrix`/`load_vectors` refuse 0 cases (opt-in `allow_empty` only where legitimate: golden pruning, fuzz seeds). |
| 2 | Invalid-UTF-8 stdout collapsed to `MATCH` — `decode("replace")` mapped *different* byte sequences to the same U+FFFD. | `decode("backslashreplace")` end-to-end; distinct bytes stay distinct in the verdict. |
| 3 | The differential fuzzer latin-1-decoded then UTF-8-re-encoded its bytes, so it never actually fed the 0x80–0xFF inputs its threat model targets. | Feed raw bytes via `stdin_bytes`; `run_one` writes them verbatim. |
| 4 | A `SAFETY:` substring inside a *string literal* satisfied the unsafe-audit gate (`unsafe { f("// SAFETY: x") }` passed). | The marker must sit inside a real comment span (`_first_comment_index`). |
| 5 | `scan_c_flaws` had **no** `memcpy`/`memmove` check — the marquee CWE-120/787 sink — and missed pre-computed overflow (`t = n*w; malloc(t)`). | Both added; a Phase-0 scan of overflowing C no longer returns "0 flaws". |
| 6 | Use-after-free detection stopped at the first `}`, missing any UAF across a nested block. | Brace-depth window (`_cut_at_block_end`) instead of first-brace cutoff. |

## 4. The gate that graded the gates was itself failing open

The sharpest finding of the docs/integrity lens is worth its own section because
of what it is: **the gate born to make lesson-pinning fail-closed was itself
failing open.**

`check_lessons_pinned.py` (added in the previous pass, from LESSONS #13) enforces
that every LESSONS entry whose `Section amended:` field names a code file is
actually cited in that file — so `make check-kit` is the lessons' own regression
suite. But its path extractor is a single regex over the field text, and a long
`Section amended` list is markdown-wrapped. When a wrap fell **mid-path, right
after a `/`** (`harnesses/cando/`⏎`cando_diff.py`), the regex matched *neither*
half and silently skipped that file. LESSON #14's own field wrapped
`harnesses/unsafe-audit/`⏎`audit_unsafe.py` exactly this way — so the gate was
**not checking `audit_unsafe.py`'s pin at all**, and reported success.

A gate that silently checks fewer things than it claims is the purest form of the
LESSONS #6 anti-pattern, and finding it *inside the enforcement gate itself* is
the audit earning its keep. **Fixed:** the extractor now rejoins whitespace that
immediately follows a `/` before matching, with a pinned self-test (a line-
wrapped amended path must still be caught). Folded into LESSONS #14 as its seventh
recurrence.

## 5. The honest verdict

The kit is genuinely good at one thing and the audit made it better at it:
**mechanical, fail-closed gates that refuse to pass while checking nothing.** That
property is now real across 22 gates, verified by reverting a real fix and
watching the suite go red. Do not undersell this — most "safety tooling" cannot
survive its own degenerate cases, and this now can.

But three honest limits remain, and a comprehensive retrospective names them:

- **"Safer than the C" is, today, mostly *mechanical* safety.** The kit reliably
  delivers memory-safety scaffolding (`#![forbid(unsafe_code)]` on core, the
  unsafe-audit gate, sanitizer *self-tests*) and *no-silent-drift* from the C
  oracle. What it does **not** yet supply is the *design* insight that avoids a
  hazardous pattern in the first place (LESSONS #1's residual — the hang the kit
  can make visible early but cannot teach you to design around). The gates prove
  the port didn't get *worse*; they do not author the safer design.

- **The compounding loop is real but has only ever fed on itself.** All 14
  lessons come from the kit reviewing its own harnesses or driving one toy
  (`examples/adler32`). Zero lessons come from foreign C. And the 14 entries
  cluster into far fewer *distinct* ideas — fail-closed gates (#6, recurring
  through #13 and #14), execution-beats-reading, shared-fidelity architecture,
  assert-don't-suppress, docs-drift-is-a-gate, environment-assumptions-cost-time,
  one-stream-per-trunk — roughly seven principles being refined ever deeper, not
  breadth being discovered. That is exactly the signature of a self-fed loop: it
  sharpens what it already knows. The single highest-value thing the kit could do
  is what `RETROSPECTIVE-kit-v1.md` §5 item 1 already says — **port real, foreign,
  CVE-bearing C** — and let LESSONS 015+ come from code the kit did not write.

- **Several controls are self-tested but never run for real.** The sanitizer,
  perf, and CI gates all pass their *self-tests* in the toolchain-free
  `check-kit`, but the miri/asan/ubsan/tsan passes have never executed against a
  real toolchain, so "UB-free" remains a claim backed by self-tests rather than an
  observation backed by a run.

  > **Correction, 2026-07-25 — this bullet was half wrong within the hour.** As
  > first written it also said the kit's own CI workflow "has never executed,
  > because GitHub Actions is policy-blocked in this repo (LESSONS #10)." That was
  > inherited from earlier sessions and **is no longer true**: Actions runs here
  > now, and this audit's own PR went green on all three jobs — `check-kit` (22
  > gates), the skeleton workspace (fmt + clippy `-D warnings` + build + test), and
  > the adler32 exit test. That is the *first observed* CI success in the project,
  > and it partially discharges what §6 item 3 below asked for. The residual is
  > genuinely narrower than the original claim: the **sanitizers** and the
  > **`porting-ci` template** (as opposed to the kit's own workflow) are still
  > unexercised. Left visible rather than silently rewritten — see LESSONS #15: an
  > inherited environment constraint is a *dated observation*, not a standing fact,
  > and repeating one unverified is how a retrospective ships a false claim.

## 6. The v1.x backlog — what this pass did NOT fix, and why

Prioritized. Each item is grounded in a fact verified this pass, and each was
left unfixed for a stated reason (usually: it needs a design decision the porting
team owns, or a real toolchain/port this repo can't provide).

**Burn-down status** (updated as items land, so this stays the live backlog rather
than a snapshot): ✅ **2** (threat-model gate), ✅ **4** (ledger name collisions),
✅ **6** (orphan linked), ✅ **7** (gate count) — all closed 2026-07-25. Item **3**
is partially discharged (CI now runs; sanitizers still don't). Items **1**, **5**,
**8** remain open, plus the keystone: port foreign C.

**P1 — could let an unsafe port through:**

1. **Workspace unsafe-doc lints are `warn`, not `deny`.** `skeleton/Cargo.toml`
   sets `undocumented_unsafe_blocks = "warn"` and `missing_safety_doc = "warn"`.
   The toolchain-free `audit_unsafe` gate hard-fails on undocumented *blocks*, but
   the clippy belt-and-suspenders that also covers `unsafe fn` is advisory — a
   real target build won't fail on it. *Not flipped unilaterally:* setting `deny`
   can break a port whose existing code has undocumented unsafe, so whether to
   flip is the porting team's call at kickoff. Flag, don't force.
2. ✅ **CLOSED 2026-07-25 — nothing enforced that the threat model gets filled.**
   `skeleton/THREAT-MODEL.md` is a 37-line template whose first line is `# Threat
   model — <project>`; a port could reach cutover with the `<project>` placeholder
   intact and no gate noticed. Now `harnesses/threat-model/check_threat_model.py`
   hard-fails on a leftover `<placeholder>`, a `TODO`, or an unreplaced `- e.g.`
   guidance bullet, and — fail-closed — on a **missing** file or a **missing
   required section**, so the check cannot be dodged by deleting the section that
   still had placeholders. Two modes, because the kit's own copy is legitimately
   still blank: `--template` (structure only) is what `check-kit` runs against the
   skeleton, guarding template rot; the default filled mode is wired into
   `porting-ci.template.yml` as a `threat-model` job for a real port.
3. **Sanitizers never run against real code** (see §5 third bullet, and its dated
   correction — CI itself *now runs and passes*, so this item is **partially
   discharged**). The residual: miri/asan/ubsan/tsan against real ported code, and
   the `porting-ci` template exercised in anger. Discharge via
   `RETROSPECTIVE-kit-v1.md` §5 item 1 — do a real port.

**P2 — could mis-grade a real port:**

4. ✅ **CLOSED 2026-07-25 — the ledger truncated case names at the first colon.**
   `load_ledger` did `name = body.split(":", 1)[0]` after stripping the pin, so a
   case named `parse:header` harvested as `parse`; two vectors differing only after
   a colon collided and one entry could suppress a divergence in the *wrong* case.
   Two fixes: a colon-bearing name is now expressible by backtick-quoting it
   (``- [x] `parse:header` [sha256:..]: why``), and a name harvested **twice is a
   hard error** instead of a silent `dict` overwrite — which also closes the
   related fail-open where a duplicate entry's later pin silently won over the
   earlier one. Truncation collisions now announce themselves at parse time.
5. **The perf gate is wall-clock and inherently flaky.** `perf_gate.py` compares
   a ratio against a default 1.3× threshold over N repeats; on a noisy CI runner
   this can false-fail or false-pass. Acceptable as an advisory gate; should be
   documented as non-blocking-by-default rather than presented as a hard gate.

**P3 — hygiene and honesty:**

6. ✅ **CLOSED 2026-07-25 — `CODE-REVIEW.md` was an orphan.** The 19 KB snapshot
   review (frozen at `9aa5984`) was linked from no other document, so a reader
   wouldn't find it or know it was frozen. Kept (it is the evidence behind LESSONS
   006–008) and now linked as a dated historical artifact from
   `RETROSPECTIVE-kit-v1.md`'s document map.
7. ✅ **CLOSED 2026-07-25 — the "14 gates" prose count had drifted** (`check-kit`
   runs 22). Corrected via a dated status note at the top of
   `RETROSPECTIVE-kit-v1.md` rather than by editing the body: the body is a
   point-in-time record and "14" was true when written, so rewriting it would
   falsify history. The note carries the current count and points to this document.
   Prose counts remain outside the doc-flags gate's reach — the durable fix is to
   stop hard-coding them, which the note now does by deferring to `make check-kit`.
8. **`progress.py` trusts that a well-formed report reflects a real run.** Ingest
   is correctly fail-closed on *malformed/missing* reports, but it cannot detect a
   *stale* or hand-authored `--json` report that is shape-valid. A run-provenance
   stamp (git SHA + timestamp the ingest verifies against the tree) would close it.

## 7. Bottom line

The audit's job was to assume the kit was lying about its own safety and prove it.
It did: the flagship exit test would have passed with the vulnerability re-
introduced, and the gate meant to keep lessons honest was skipping the very file
it was pointed at. Both are now fixed, pinned, and proven by execution — the port
can no longer silently un-fix its C defect, and no amended file can silently go
un-pinned. What the audit could **not** do from inside this repo is buy the kit
the one thing it most needs: a lesson from foreign C. That remains v1.x item one.
The kit is now honest about what it verifies; the next retrospective should be
written from someone else's codebase.
