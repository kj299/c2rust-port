# RETROSPECTIVE — the probe harness, and the gates that were never runnable

Closing retrospective for the **probe-then-port harness** (`harnesses/probe/`,
PR #24) and the audit that followed it, run per `PROMPTS/90-retrospective.md`.
The harness itself was the previous retrospective's named next target
(`RETROSPECTIVE-cjson.md` §6): the mechanical form of LESSONS #17, so a
hand-written test expectation that contradicts the C cannot exist.

It shipped and works. **This retrospective is about what shipping it exposed** —
including a defect in a *neighbouring* harness that had been live since before
v1.0, and a hole I introduced in the very change that closed the last one.

## 1. Step 0, executed (this is where every finding came from)

Not narrated — run. `make check-kit` green (16 gates + integrity checks); the
gate-mutation sweep green (15 gates, 0 survivors); then the part that matters:
**probing what each gate does not look at**, and **re-testing every inherited
"doesn't work here" claim** (LESSONS #15).

| Probe | Result |
|---|---|
| Re-test "asan/ubsan were not run" (cJSON §7) | **asan runs here in one command**, clean over `cjson_core` + `cjson_ffi` |
| Run `run_sanitizers.sh ubsan` for real | **rc=1 on any codebase** — `-Zsanitizer=undefined` is not a thing |
| Run its `--check` self-test | **rc=0** — it validated bash syntax and nothing else |
| Delete a module's probes and re-gate | **nothing failed** — no gate asks whether a module has probes |
| Ask what the mutation sweep covers | **python only**; its "0 survivors" excluded every bash harness |
| Check `sanitized` in a container without miri | still reports **green**, from a run in a container that no longer exists |

Four of the six are defects. None was findable by reading; all six took one
command each.

## 2. The gate that could never go green (→ LESSONS #22)

`run_sanitizers.sh ubsan` ran `RUSTFLAGS=-Zsanitizer=undefined`. **rustc has no
`undefined` sanitizer** — Rust's UB detector is miri — so the mode failed on
every codebase in the world, and `all`, which included it, was permanently red no
matter how clean the code.

The kit is built around fail-closed gates, so a gate that can *only* fail looks
harmless. It isn't: it is unusable, so it gets skipped, and a skipped control is a
broken control. This one had been live since before v1.0 and survived three things
that exist to catch exactly it:

1. **PR #1's 26-finding review** — whose High findings included a *never-runnable
   sanitizer job*. The same defect, in the same harness family, one layer down.
2. **Every gate-mutation sweep** — because `_run` hardcoded `sys.executable`, so
   no bash harness could be in the table at all, while the sweep printed
   *"15 gate(s) mutated, 0 survivor(s)"*, which reads as the whole gate set.
3. **A complete foreign port** — because the cJSON port **hand-rolled its own
   `cargo +nightly miri test`** rather than calling the harness. In the kit's
   entire life, `run_sanitizers.sh` had never once executed against real code.

And a documentation failure kept anyone from looking: `RETROSPECTIVE-kit-v1.md`
carried a status note of mine claiming the sanitizer gap was closed because miri
"now runs against that port". The *port* ran miri; the *harness* never ran at all.
A status note that credits a duplicate for closing a gap is worse than an open
gap, because it stops the search. Corrected in place with a dated note.

**Fixed:** modes validate through `is_valid_san` against the list rustc accepts;
`--check` pins that validator with a **negative fixture** — it must reject
`undefined`, the exact value that shipped — and cross-checks against a live
nightly rustc; `ubsan` delegates to miri with an explanation; `all` = miri + asan;
`-- <cargo args>` pass-through so a port can scope the run instead of duplicating
it. `mutate_gates._run` dispatches by extension, so **bash gates are sweepable for
the first time**, and the sanitizer gate is in the table (mutation → self-test red,
verified). The cJSON port now calls the harness, and runs **asan** alongside miri.

## 3. The gate above the gate (→ LESSONS #23)

`probe.py` fails closed on everything *inside* its inputs: zero probes in a file,
a hanging oracle, a tampered transcript, a hand-edited generated test. All true,
and all beside the point — because **which probes files exist** was a hand-edited
line in the port's `check.sh` naming one file. A module could land with no probes
at all and every gate stayed green.

That is the kit's characteristic 0-of-0 (LESSONS #6/#14/#18/#20) displaced one
level up, into the wiring — committed **by me, in the same change that mechanized
the lesson about conventions decaying**. A gate hardened against everything inside
its input is still trusting whoever picked the input.

**Fixed:** `probe.py coverage` reads the module list from the port's own
`progress.json` — so it cannot drift from the list the gates track — and fails
naming any module without probes; an empty module list is itself a failure.
Probes files carry `modules: [...]` tags, reusing the Phase-2 corpus tagging idiom
(LESSONS #19).

## 4. What writing the missing probes found

The two uncovered cJSON modules (`alloc-node`, `buffer-plumbing`) were "covered"
in the sense that the differential and fuzzer exercised them. Probing them
directly pinned **four behaviors reasoning would have gotten wrong**:

| Probe | The C actually does |
|---|---|
| leading UTF-8 BOM | **accepted** (`skip_utf8_bom`) — `﻿{}` parses |
| `[1] xyz` | **accepted**, yields `[1]` — trailing garbage is not an error |
| `[1,\x002]` | **accepted**, yields `[1,2]` — an embedded **NUL is whitespace** (`buffer_skip_whitespace` tests `<= 32`) |
| empty object, formatted | `{\n}` — while an empty array prints `[]`. Asymmetric |

The port already matched all four; the differential corpus and 6000 fuzz
iterations had driven it to fidelity without anyone naming these. That is the
gates working. But they were **unnamed**, and an unnamed behavior is one a future
maintainer "cleans up": NUL-as-whitespace looks exactly like a bug worth fixing,
and fixing it would silently break drop-in parity. They are now generated tests
with the C's bytes and a note each. This is §2 of the cJSON retrospective all over
again — *the C is a spec only the oracle can read* — and it keeps being true even
for modules already through six gates.

## 5. What held up

- **The harness did its job on first contact.** `probe.py verify` caught a
  one-byte hand-edit to a generated file and a stale regeneration, both on the
  first try, and the gate-mutation entry proved its drift verdict is load-bearing.
- **The fail-closed reflex is now automatic** and it is the right reflex: every
  new subcommand got its 0-of-0 case (`NOTHING-TO-PROBE`, `NOTHING-TO-COVER`)
  without being asked.
- **`check_lessons_pinned` did its job**: 41 lesson→code links, and the count rose
  by exactly the five paths the two new lessons name — verified by arithmetic, not
  by trusting the green (the habit that found the `ports/` gap last time).
- **Re-probing inherited claims paid again** (LESSONS #15, third consecutive
  retrospective): "Actions is blocked" → it wasn't; "miri isn't available" → it
  was; "asan wasn't run" → it runs in one command and finds nothing.

## 6. The failure the kit still would not prevent

**Two, and they are the same shape as everything above — a control whose *scope*
is chosen by hand.**

1. **`sanitized` is the only gate rung with no machine-checked evidence.** Five of
   six rungs advance by ingesting a harness's stamped `--json` report, whose
   provenance `progress.py` verifies against HEAD. `sanitized` has no report: the
   port's `check.sh` sets it directly, correctly refusing to on a SKIP — but
   **nothing ever un-sets it**. `progress.json` is committed, so the claim
   outlives the evidence: this session began in a fresh container with **no miri
   installed at all**, and the cJSON port still read fully-gated on every module.
   The next target is a stamped sanitizer report ingested like the others, so the
   rung expires with its provenance instead of living forever.
2. **The mutation table is hand-maintained, and nothing requires an entry.**
   Fixing `_run` made bash gates sweepable; it did not make them swept. Measured:
   **20 harness scripts expose a self-test, and 3 have no mutation entry** —
   `gen_fuzz_target.sh`, `run_supply_chain.sh`, `check_skeleton.sh`, all bash, all
   in the blind spot that hid LESSONS #22 for a month. The fix is the same move
   this retrospective made twice already: a coverage check *over the checker* —
   every harness with a self-test must appear in the table or the sweep fails.

Both are the lesson the kit keeps re-learning at successively higher altitudes:
**hardening what a gate inspects does nothing about what it was pointed at.**
It has now been bitten at the verdict (LESSONS #6), the input (#14, #18, #20), the
wiring (#23), and the tool inventory (#22). Next time, ask the scope question
first.

> **Status — 2026-08-22 (same day, follow-up change): both closed.**
>
> **Item 1 → LESSONS #24.** `run_sanitizers.sh --json` now emits a
> provenance-stamped report of what actually ran (`modes_run`, `rc`), built from
> the kit's own `provenance_stamp` rather than a bash reimplementation;
> `progress.py --sanitize-json` advances `fuzzed → sanitized` only when a checker
> genuinely ran and exited 0. The port stopped hand-setting the rung, and its
> committed `progress.json` was **reset to `ported` and re-earned** — all 7
> modules climbed all four evidence rungs in one ingest. Probed both failure
> modes live: a report from another commit is refused as STALE, and a correctly
> stamped report where nothing ran advances nothing. The port now runs the
> harness's `all` mode, so one report records **both** miri and asan
> (`modes_run=['miri','address']`) instead of under-reporting an unrecorded pass.
>
> **Item 2 → LESSONS #25.** `coverage_gaps()` fails a full sweep naming any
> self-tested harness with no mutation entry; exemptions must carry a written
> reason (one: the mutator itself). Adding entries for the three remaining bash
> gates immediately produced **three survivors** — each self-test only ever
> exercised the happy path, so neutralizing its verdict changed nothing it
> observed. Each crown verdict was extracted into a predicate (`valid_target`,
> `have_deny_template`, `skel_present`) and given a **negative fixture**. Sweep:
> **19 gates, 0 survivors, 0 table gaps** (was 15 gates, python-only).
>
> The §6 thesis stands and is worth restating, because the fix for item 2
> demonstrated it twice in one sitting: making a blind spot *reachable* is not
> making it *covered*.

## 7. Honest remainder

- asan ran over `cjson_core` + `cjson_ffi` **without `-Zbuild-std`**, so `std`
  itself is uninstrumented. That is the right default (build-std is slow and needs
  `rust-src`), but it means asan here covers the port's own code and its FFI
  boundary, not allocations made inside `std`.
- `tsan`/`lsan` are wired and validated but not run: the port is single-threaded
  and leak-checking a `forbid(unsafe_code)` core has little to find.
- The three bash gates in §6.2 are unswept **today**, not merely unsweepable.
