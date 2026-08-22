# RETROSPECTIVE — cJSON, the kit's first foreign port

Closing retrospective for the **cJSON v1.7.18 → Rust** port (`ports/cjson/`), run
per `PROMPTS/90-retrospective.md`. This is the port the kit's own backlog kept
naming as its keystone: every prior lesson came from the kit reviewing itself or
driving one toy (`examples/adler32`). **LESSONS 001–016 were self-fed; 017–020
come from someone else's C**, which is where the kit was always meant to spend.

Outcome: **7/7 modules through all six gates** — `ported → differential → fuzzed
→ sanitized → unsafe-audited`. The Rust library is a **verified drop-in `.so`**
for cJSON's parse/print/minify surface, with **zero unsafe outside one audited
FFI crate** (33 blocks, every one `// SAFETY:`-documented) and miri clean.

## 1. What was built

| | |
|---|---|
| Source under port | cJSON v1.7.18 (MIT, git `acc76239`), 3143 LOC of `cJSON.c` + header, SHA-pinned in `c/PROVENANCE.md` |
| Rust | `crates/core` (`#![forbid(unsafe_code)]`), `crates/ffi` (`libcjson_rs.so`, the only unsafe), `crates/driver` (differential driver) |
| Oracle | C driver + `.so` built from the pristine source; **86 vectors**, every one validated against C before it was allowed to judge Rust; 7 held back as a hidden acceptance set |
| Gates | differential (79/79), `dup`/`dup-eq` DOM differentials (69/69 each), diff-fuzz in 3 modes, miri, unsafe-audit, ABI-level `lib_diff` (15/15) |
| Increments | 8 PRs (#15–#22), each CI-green before merge |

## 2. The port's central finding: the C is a spec only the oracle can read

**Every substantive mistake I made was made by reasoning about the C instead of
running it.** Four, all caught by execution, none findable by reading (→ LESSONS #17):

1. **`print(DBL_MAX)` is lossy and the C is fine with it.** I wrote the test
   asserting the reasoned answer — 15 digits can't round-trip DBL_MAX, so the
   17-digit fallback fires. Wrong: the `%1.15g` form reparses as **inf**, and
   `compare_double(inf, d)` = `nan ≤ inf` = **true**, so the C accepts the failed
   round-trip. `print → reparse → print` yields `null`.
2. **`cJSON_Compare` denies that a value equals its own duplicate** — for inf/nan
   (same quirk) and for any object with **duplicate keys** (first-match lookup
   can't resolve the second). Surfaced when the `dup-eq` matrix's C-baseline
   validation *refused my vectors* for asserting `"true"`.
3. **`cJSON_Minify` ignores escape parity** — `\` before `"` escapes it even when
   the backslash is itself escaped, so `"\\" "` keeps its space. My "correct"
   implementation dropped it. Found by **differential fuzzing**.
4. **`parse_hex4` returns 0 on invalid hex**, so `"\uZZZZ"` becomes a NUL byte
   rather than an error — and the printer then truncates there.

The through-line: a mature C library's behavior is a thicket of accreted quirks,
several of which look like bugs and some of which are. A port that silently
"cleans them up" is not safer — it is *differently wrong*, and the difference is
invisible to everyone downstream. Faithfulness is a per-quirk decision made with
the C's actual bytes in hand. **Kit change:** probe-then-port is now a Phase 4
entry criterion and step 0 of the module prompt/skill.

## 3. The gates that were green because they were empty

For six of seven increments `audit_unsafe.py` printed **"unsafe blocks: 0,
documented: 0, undocumented: 0"** and exited 0 — and I read that as passing. It
wasn't: the core is `forbid(unsafe_code)`, so there was *nothing to audit*. The
gate only said anything once the FFI crate landed.

Worse, and entirely my own doing: I asserted **"miri/asan need toolchains this
environment lacks"** across five increments and left `sanitized` unset — an
inherited environment claim I never re-tested, which is precisely **LESSONS #15,
written by me, in this same session**. The retrospective's step-0 probe took one
command: `rustup toolchain install nightly --component miri` **succeeded**. Miri
then ran clean over the whole port, and I verified it fail-closed by injecting an
out-of-bounds read (miri caught it, exit nonzero). The `sanitized` gate was
available the entire time.

Both are one failure: **a believed-covered control that inspected nothing**, and
both render green. → LESSONS #18, and the fixes: `audit_unsafe` now prints
`NOTHING-TO-AUDIT` and reports `blocks_found`, `progress.py` refuses to advance
`unsafe_audited` on a 0-of-0 report, and the port's `check.sh` advances
`sanitized` **only when miri actually ran** (never on a SKIP), with nightly+miri
in CI.

## 4. What the process got right

- **Oracle-first paid immediately.** Locking 86 C-validated vectors *before*
  writing Rust meant every increment had a real verdict, and the C-baseline
  validation (`a vector must pass on C before it may judge Rust`) caught two of my
  wrong assumptions before they became wrong code.
- **Module-tagged corpus** (→ LESSONS #19). A 7-module port can't diff the full
  matrix from increment one; tagging each vector with the modules that decide it
  and filtering to `matrix-ported.json` kept every increment's differential
  meaningful *and* 100% green (25 → 44 → 69 → 79 as modules landed).
- **Fuzzing found what review couldn't.** The minify escape-parity divergence was
  invisible to reading and to 79 hand-written vectors. Fuzz → find → fix-forward →
  pin, in one change, then 6000 iterations clean.
- **The gates are not decorative.** Probed at cutover: disabling the
  `NESTING_LIMIT` guard makes the differential go red (`cve-nesting-1001`
  diverges, exit 1); injecting UB makes miri exit nonzero. Both controls are real.

## 5. What the port gave back to the kit

Three defects in the kit itself, all surfaced only by *using* it on foreign code:

1. **`lib_diff --json` crashed** on a bytes-valued (`cstr`) return — it had a full
   self-test suite, survived the gate-mutation sweep, and had driven adler32, but
   nothing had ever pushed a bytes return *through the JSON report*. → LESSONS #20;
   fixed with `_jsonable` (backslashreplace, byte-faithful per LESSONS #14) + pin.
2. **`check_lessons_pinned` couldn't see `ports/`.** Its path extractor knew
   `harnesses|skills|skeleton|examples|.github` — a prefix list that predated the
   existence of `ports/`. LESSONS #19 named `ports/cjson/oracle/gen_corpus.py` and
   the gate **silently checked nothing**. Found by verifying the gate's output
   instead of trusting its green. Fixed + pinned.
3. **`audit_unsafe`/`progress` 0-of-0 blindness** (§3), fixed as above.

Note the pattern: #1 and #2 are the *same* failure as #3 — a control reporting
success over an empty set. The kit has now been bitten by this at least four
distinct times (LESSONS #6, #14, #18, and here). It is the kit's characteristic
bug, and the only durable answer found so far is the gate-mutation harness plus
the habit of *reading what a gate says it checked*, not just its exit code.

## 6. The failure the kit still would not have prevented

**Nothing forced me to probe the oracle before writing each module.** All four
§2 mistakes were caught — by the differential, the fuzzer, or a matrix's
C-baseline validation — but *after* I had written wrong code and wrong tests to
match. The gates are excellent at refusing bad code; they do nothing to stop it
being written, and a wrong unit test written from reasoning will happily agree
with wrong Rust until something external disagrees. LESSONS #17 addresses this
with a *convention* (probe-then-port, paste the transcript), and conventions are
exactly what LESSONS #13 says decay without a control.

**The next port's target:** a mechanical form of probe-then-port. Something like
a `probe.py` that takes a module's edge-case inputs, runs the oracle, and emits a
transcript the module's tests are *generated from* — so a hand-written expectation
that contradicts the C cannot compile, rather than merely failing later. Until
that exists, "the C is a spec only the oracle can read" is a habit, not a gate.

> **Status — 2026-07-25 (same day, follow-up change):** delivered as
> `harnesses/probe/probe.py` (LESSONS #21). `run` pins the C's observed bytes
> under a fingerprint, `gen` generates the Rust `#[test]` expectations from the
> transcript, `verify` fails closed on oracle drift / transcript tamper /
> hand-edits to the generated file. This port's eight §2 quirks are the worked
> integration (`oracle/probes-quirks.json` → `crates/core/tests/probes_quirks.rs`,
> verified in `check.sh` step 1b), and the gate-mutation sweep covers the new
> verdict. The habit is now a gate.

## 7. Honest remainder

- The FFI exposes parse/print/minify/compare/duplicate; the **struct-field ABI**
  (a caller reading `item->valueint` directly) and the full `Add*`/`Get*` builder
  surface over FFI are unported. The safe-Rust implementations exist in
  `crates/core`; exposing them is mechanical, not conceptual.
- `cJSON_Utils` (JSON-Pointer/Patch/Merge, 1481 LOC) was out of scope throughout.
- **asan/ubsan** were not run (miri was). The `sanitized` gate is honest about
  what it verified: miri over the FFI + core.
  > **Superseded — 2026-08-22.** Re-probed per LESSONS #15 and both halves were
  > wrong in opposite directions. **asan runs here in one command** and finds
  > nothing over `cjson_core` + `cjson_ffi`; it is now part of `check.sh`, not a
  > remainder. **ubsan does not exist for Rust at all** — `-Zsanitizer` has no
  > `undefined` value, so the kit's `run_sanitizers.sh ubsan` had been a
  > permanently-failing gate (LESSONS #22). Listing it here as an unclosed gap
  > implied it was a thing that *could* have been run.
- Custom-allocator parity (`cJSON_InitHooks`) is **deliberately dropped and
  ledgered** (CWE-362 — process-global mutable allocator hooks are a data race the
  port refuses to reproduce).
