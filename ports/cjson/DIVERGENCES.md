# Intentional divergences from the C original — cJSON port

Every place the Rust port **deliberately** behaves differently from cJSON v1.7.18.
The differential (`diff_run.py --ledger DIVERGENCES.md`, and `lib_diff`/`cando`)
reads this file: a case listed here as `- [x]` is a known-intentional divergence,
suppressed (reported `DIVERGE(ledgered)`, not a failure). Pin each with the
fingerprint the tool prints, so a *changed* divergence re-fails (LESSONS #8), and
note that a ledgered case that stops diverging is a `LEDGER-STALE` failure
(LESSONS #14) — a ledger asserts the divergence still occurs.

Format:

```
- [x] <case-name> [sha256:<12-hex>]: <why the Rust intentionally differs; CWE if a security fix>
```

## Confirmed divergences

- [x] `custom-allocator-dropped`: **cJSON_InitHooks / global_hooks not
  reproduced** (CWE-362, race condition / thread-safety). cJSON keeps a
  process-global MUTABLE `internal_hooks global_hooks` (cJSON.c:186) that
  `cJSON_InitHooks` overwrites — any thread calling it mutates allocation
  behavior for all others, with no synchronization. The Rust port uses the
  global allocator and offers no `InitHooks` equivalent, so this shared-mutable-
  state hazard is designed out rather than ported. This is a *safety* divergence
  (the port refuses to reproduce a data race), not a missing feature; it changes
  no parse/print/minify output, so it produces no differential divergence — it
  is recorded here as the deliberate decision (THREAT-MODEL §5, agreed at the DOM
  module). Not fingerprint-pinned: there is no observable output diff to pin; the
  assertion is architectural (no `cJSON_InitHooks` symbol will exist in the FFI
  crate).

No output-level divergences yet: every ported module matches the C byte-for-byte
(the `dom` module's Compare/Duplicate quirks — inf never equals itself, dup-keys
never compare equal — are REPRODUCED, so they are matches, not divergences).

## Candidate divergences (anticipated in Phase 0/2 — decide when the module lands)

These are behaviors where the port is *expected* to face a match-or-improve
choice. They are NOT ledgered yet (no `- [x]`); each becomes a real entry only if
the port diverges and the divergence is judged an intentional fix-of-C-defect.

- **Trailing-garbage laxness.** cJSON's default `cJSON_Parse` accepts input with
  trailing bytes after the first complete value (`{"a":1}trailing` → `{"a":1}`,
  rc 0; `123 456` → `123`). This is the `require_null_terminated=false` default.
  A stricter Rust port could *reject* trailing garbage (safer: a truncated/spliced
  document is usually an attack or a bug). If it does, the `trailing-garbage-lax`
  vector will DIVERGE (Rust rc 1 vs C rc 0) and must be ledgered here as an
  intentional strictness improvement — OR the port matches C's laxness and no
  entry is needed. **Decision deferred to the `entry-minify` module.**

- **Number re-formatting.** `print_number` uses `%1.15g`/`%1.17g` with a
  round-trip check (cJSON.c:553–620). If Rust's float formatting produces
  different (but numerically equal) bytes for any value, the round-trip vectors
  DIVERGE and each such value is ledgered. **RESOLVED at `scalar-parse`
  (2026-07-25): no divergence.** The port re-implements C's `%g` byte-for-byte
  (`num.rs::fmt_g`) — 25/25 scalar vectors MATCH, including the discovered
  **DBL_MAX lossy-print quirk**: C's 15-digit form `1.79769313486232e+308`
  reparses as *inf* (it rounds above DBL_MAX), and `compare_double(inf, d)` is
  `inf <= inf·ε` → *true*, so C keeps the lossy form and never falls back to 17
  digits — meaning `print(DBL_MAX)` → reparse → reprint yields `null`. The port
  reproduces this faithfully (pinned in `num.rs` tests and the
  `dbl-max-lossy-print` / `dbl-max-reparse-null` vectors, both validated against
  the C). A future *fix* of this lossiness would be a ledgerable divergence;
  today it is exact-match behavior.

- **Parse error position / text.** The driver keeps error offsets on STDERR (off
  the compared contract) precisely so error-message wording need not match. If a
  future contract puts error detail on stdout, expect divergences here.

## Structural eliminations (NOT divergences — no output change)

These historical-CVE classes are eliminated by Rust's type system and produce
**no observable divergence**, so they never appear as ledger entries — they are
recorded in `FLAW-SCAN.md` as the port's safety win: use-after-free (#248),
dangling-realloc arbitrary write (#189), out-of-bounds read/write (#230, #338,
a167d9e), NULL-deref (CVE-2024-31755, CVE-2023-50471/50472). The port reproduces
the same *observable* behavior (same output, same accept/reject) by a *safe*
construction; the differential confirms the behavior matches, and the safety is
the invisible dividend.
