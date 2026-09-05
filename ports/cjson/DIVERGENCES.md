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

- [x] `utils-tilde-add` [sha256:fc9bc27df6e4]: **JSON Patch mis-decodes a `~1` escape in a child key**
  (CWE-707, improper neutralization → wrong-target write). `cJSON_Utils.c`'s
  `decode_pointer_inplace` writes `decoded_string[1] = '/'` where `[0]` is meant,
  so `add path:"/a~1b"` (RFC 6901: key `a/b`) builds the key `a~/` instead — a
  patch silently lands on the wrong key, and the trailing byte is dropped. The
  port decodes the child key correctly per RFC 6901 (`a/b`). JSON Pointer *get*
  is already correct in the C — only the Patch decoder is broken. Confirmed by
  probing v1.7.18; fixed and pinned in `utils::tests`.
- [x] `utils-tilde-add0` [sha256:cd251cc8eac9]: same defect for the `~0` escape: `add path:"/a~0b"`
  (key `a~b`) builds `a~0` in the C; the port builds `a~b`.
- [x] `utils-tilde-remove` [sha256:2e225c9b006d]: the same mis-decode makes `remove`/`replace` of an
  escaped-key path FAIL (the C returns status 13, document unchanged) because
  the corrupted child key matches nothing; the port decodes correctly and
  removes `a/b` (status 0). All three are one C defect
  (`decode_pointer_inplace` writes `decoded_string[1]` where `[0]` is meant),
  fixed once in the port's `decode_pointer_inplace`. That port function is
  otherwise a faithful simulation of the C's in-place decoder: an INVALID escape
  still yields the same partial/raw key, so only the `~0`/`~1` write diverges.
  The separate GetPointer decoder (`decode_token`, mirroring `compare_pointers`)
  was already correct in the C and is ported as-is.

- [x] `construct-nan-double-quiet` [sha256:ff80ae78004c]: **`cJSON_CreateNumber(NaN)`
  converts a NaN to `int`** (CWE-758, reliance on undefined behavior).
  `cJSON_CreateNumber` saturates `valuedouble` into `valueint` with two guards
  (cJSON.c:2460): `num >= INT_MAX` and `num <= (double)INT_MIN`. Every
  comparison with a NaN is false, so a NaN falls past both and reaches
  `item->valueint = (int)num` — undefined behavior (C17 6.3.1.4p1: undefined if
  the truncated value cannot be represented). It is undefined in a way that
  *actually differs per target*, not merely in theory: x86-64's `cvttsd2si`
  yields INT_MIN (probed: `-2147483648`), AArch64's `fcvtzs` yields 0. Rust's
  `as` cast is defined to saturate and to map NaN to 0, so the port answers
  **0** — the defined answer, and the one shipped cJSON already gives on
  AArch64. Reproducing the x86 value would mean writing
  `if d.is_nan() { i32::MIN }`, i.e. deliberately encoding one platform's
  interpretation of undefined behavior into a port whose whole purpose is to
  remove it.
- [x] `construct-nan-double-negative` [sha256:dc773701b885]: same defect, negative NaN.
- [x] `construct-nan-double-signalling` [sha256:02cb3d3c3146]: same defect, signalling NaN.
- [x] `construct-nan-float` [sha256:28ec6f0d0627]: same defect reached through
  `cJSON_CreateFloatArray`, which widens each `float` to `double` before calling
  `cJSON_CreateNumber` — an f32 NaN widens to an f64 NaN, so the float array is
  a second route to the same cast.
- [x] `construct-nan-float-negative` [sha256:a4cc71562ff2]: same, negative f32 NaN.

  All five are ONE defect at one line. Why it survived six green gates: the cast
  is unreachable from *parsing*. `parse_number` (cJSON.c:374) has the identical
  code, but its character whitelist is `0-9 + - e E .`, so `strtod` there can
  return an infinity (which both guards catch) but never a NaN. Only the
  *construction* API can reach it, and no driver mode constructed a number from
  attacker-supplied bits until `dom-construct` did (LESSONS #26 yet again).
  `cJSON_SetNumberHelper` (cJSON.c:396) carries the same cast and is the third
  route; it belongs to the not-yet-ported mutation API and is recorded as
  unported in API-COVERAGE.md rather than fixed blind.

  Because the class is predicate-defined (*every* NaN, and 8 random bytes are a
  NaN about once in 2048), it cannot be pinned case-by-case for the FUZZER — so
  `construct` fuzzes against the corrected oracle (`oracle/make_fixed_core.py`,
  the LESSONS #28 mechanism that `patch` already used), where both sides answer
  0 and any finding is a real port bug. The five rows above are the finite
  assertion against *shipped* cJSON, and they fail if the divergence ever stops
  happening.

- [ ] `scalar-parent-child` — **NOT YET ON THE COMPARED CONTRACT.** `cJSON`'s
  `add_item_to_array` / `add_item_to_object` never check that the parent is a
  container: their only guards are NULL and self-reference. Probed against
  v1.7.18: `cJSON_AddTrueToObject(node, "k")` succeeds on an array, a number, a
  string, `true` and `null` alike, hanging a child off a scalar. The printer
  ignores that child (a number still prints `7`), but `cJSON_GetArraySize` then
  answers 1 and `cJSON_GetArrayItem(node, 0)` hands it back — so the malformed
  tree is observable, not inert. The port cannot reproduce it: `Value::Number`
  has nowhere to put a child, so the malformed state is unrepresentable rather
  than merely rejected, and the Add helpers answer false.

  Deliberately left unledgered and ungated for now: no mode builds a
  non-container parent, so nothing observes it, and pretending otherwise with a
  ledger entry would assert a divergence no run measures (LESSONS #31 — a
  control nothing invokes). It belongs to `add_item_to_*`, which the `dom` and
  `ffi-builder` modules own, not to the twelve constructors this module gates.
  Putting it on the contract is its own increment, tracked as such.

Beyond those three JSON-Patch escape fixes and the NaN cast above, every ported module matches the C
byte-for-byte (the `dom` module's Compare/Duplicate quirks — inf never equals
itself, dup-keys never compare equal — are REPRODUCED, so they are matches, not
divergences; likewise every faithful cJSON_Utils behavior — non-recursive sort,
NULL-key array permutation, the `test`/generate in-place sort side effect, and
`generate_merge_patch`'s case-SENSITIVE key diff under a case-INsensitive sort
(`cJSON_Utils.c:1423` hardcodes `strcmp`, and its recursion at `:1455` is always
case-insensitive) — all reproduced, so they are matches, not divergences).

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

- **The typed-array constructors' unchecked `(pointer, count)` pair.**
  `cJSON_CreateIntArray` / `FloatArray` / `DoubleArray` / `StringArray` take
  `(const T *numbers, int count)` with no way to reconcile the two; a count past
  the end of the buffer is an out-of-bounds read the library cannot detect, and
  it is the only memory-safety hazard these four functions have. The port's core
  takes a **slice**, so the pair cannot disagree — the hazard is designed out
  rather than checked. This improvement is invisible to the differential *by
  construction*: exercising the mismatch would make the C oracle undefined, so
  there is no defined behavior to compare against, and `construct` therefore
  clamps every count to the elements its payload actually holds. Stated here
  because "the differential shows no divergence" must not be misread as "the
  differential checked it".

These historical-CVE classes are eliminated by Rust's type system and produce
**no observable divergence**, so they never appear as ledger entries — they are
recorded in `FLAW-SCAN.md` as the port's safety win: use-after-free (#248),
dangling-realloc arbitrary write (#189), out-of-bounds read/write (#230, #338,
a167d9e), NULL-deref (CVE-2024-31755, CVE-2023-50471/50472). The port reproduces
the same *observable* behavior (same output, same accept/reject) by a *safe*
construction; the differential confirms the behavior matches, and the safety is
the invisible dividend.
