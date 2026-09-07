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
  route; it landed with `dom-mutate-set` and is ledgered as
  `set-number-nan-*` below.

  Because the class is predicate-defined (*every* NaN, and 8 random bytes are a
  NaN about once in 2048), it cannot be pinned case-by-case for the FUZZER — so
  `construct` fuzzes against the corrected oracle (`oracle/make_fixed_core.py`,
  the LESSONS #28 mechanism that `patch` already used), where both sides answer
  0 and any finding is a real port bug. The five rows above are the finite
  assertion against *shipped* cJSON, and they fail if the divergence ever stops
  happening.

- [x] `set-string-target-type-confusion` [sha256:7c6dfc6245f8]: **`cJSON_SetNumberHelper`
  writes number fields into a node that is not a number** (CWE-843, type
  confusion). The function (cJSON.c:384) tests nothing about `object->type`
  before `object->valueint = …` and `object->valuedouble = number`, so
  `cJSON_SetNumberValue(a_string_node, 3)` leaves a node whose `type` still says
  `cJSON_String`, whose `valuestring` is still the string, and whose
  `valuedouble` is now 3. No accessor reports it — `cJSON_GetNumberValue` checks
  `cJSON_IsNumber` first and answers NaN — but `valueint`/`valuedouble` are
  public struct fields cJSON's own header documents callers reading
  (cJSON.h:110-120), so the inconsistency is observable and it outlives the call
  that made it.

  The port answers by **not being able to represent it**: `Value::String` has no
  number to write, so `dom::set_number` is a no-op on a non-number and returns
  the same `number` the C returns. That is the Prime Directive's "make the
  invariant structural" rather than a check a later edit could drop.

  The `set` driver mode prints the target's `type`, `valueint` and
  `valuedouble` precisely so this is *measured*, not asserted (LESSONS #31): the
  C row carries `i3,d4008000000000000` on a `t16` node and the port's carries
  `i0,d0000000000000000`.
- [x] `set-true-target-type-confusion` [sha256:127f73189076]: same defect onto a
  boolean, which already carries `valueint = 1` — so the C's write *replaces* a
  meaningful field rather than filling a zeroed one.
- [x] `set-null-target-type-confusion` [sha256:56ccfe9002a8]: same, onto a null.
- [x] `set-array-target-type-confusion` [sha256:4b79e1693966]: same, onto an
  array — a container node that now also claims a numeric value.
- [x] `set-object-target-type-confusion` [sha256:b854f0a045b0]: same, onto an object.
- [x] `set-string-target-then-set-string` [sha256:84bdb68edd2e]: the same defect,
  on a row where `cJSON_SetValuestring` **succeeds** first (a string target, a
  shorter replacement). It is here so the ledger pins that only the *number*
  write diverges: every string-setter field in the row (`sv`, `s2`, `sv2`,
  `svnull`, `svnum`, `doc`) matches the C byte for byte.

- [x] `set-nan-quiet-no-target` [sha256:1e215c037df1]: **`cJSON_SetNumberHelper(item, NaN)`
  converts a NaN to `int`** — the identical CWE-758 defect as
  `construct-nan-*` above, at the second of the two sites that carry that cast
  (cJSON.c:396). A NaN fails both saturation guards and reaches
  `object->valueint = (int)number`: undefined per C17 6.3.1.4p1, and
  target-dependent in fact (INT_MIN on x86-64, 0 on AArch64). The port shares
  one saturating helper with `cJSON_CreateNumber`, so it answers the defined 0
  at both sites for free. This row has NO document target, which isolates the
  divergence to the freshly-built number (`n2`/`sn2`) and proves the setter
  reaches the cast on its own.
- [x] `set-nan-quiet-number-target` [sha256:241f397092b7]: the same NaN onto a
  parsed NUMBER target as well, so both the document node and `n2` take the cast.
- [x] `set-nan-negative` [sha256:6391a5a4b77a]: same defect, negative quiet NaN.
- [x] `set-nan-signalling` [sha256:0e46ef6b51ba]: same defect, signalling NaN payload.

  Both classes above are **predicate-defined** — *every* non-number target, and
  *every* NaN — so neither can be pinned case-by-case for the FUZZER. The `set`
  mode therefore fuzzes against the corrected oracle
  (`oracle/make_fixed_core.py` now patches `cJSON_SetNumberHelper` as well as
  `cJSON_CreateNumber`), where both sides agree and any finding is a real port
  bug. The ten rows above are the finite assertion against *shipped* cJSON and
  fail if either divergence ever stops happening (LESSONS #28).

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

  **`dom-mutate-remove` came within one line of dragging it in, and declined
  (2026-09-07).** The `seq` mode needs an *append* op — that is how a corrupted
  last-item cache becomes visible at all — and an append whose target is
  fuzzer-chosen will sooner or later name a scalar or an object. The C accepts
  both and produces trees the port cannot represent: a child hung off a number,
  and an object member whose key is NULL (which prints as `""` but which
  `get_object_item` can never find, so it is not the same as an empty key). So
  the `seq` mode's `app` op refuses any target that is not an ARRAY, on **both**
  sides. That is a scope decision, not a correctness dodge, and the difference
  matters: the C has a defined answer here, so declining to compare it is
  declining, where `construct`'s clamped counts were avoiding undefined
  behaviour. It is written into `cjson_modes.h`, into `modes::seq`, and here,
  because an unstated refusal is indistinguishable from an oversight.

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

- **`cJSON_SetValuestring`'s overlapping `strcpy` (cJSON.c:418).** The
  shorter-or-equal fast path is `strcpy(object->valuestring, valuestring)` with
  nothing stopping the caller passing a pointer *into that same buffer* —
  `cJSON_SetValuestring(item, item->valuestring + 2)` is a plausible "strip a
  prefix" call and is an overlapping copy, undefined per C17 7.24.2.3. Confirmed
  live, not reasoned: ASan reports `memcpy-param-overlap` at cJSON.c:418
  (`spikes/setvaluestring_alias.c`; FLAW-SCAN.md **L4**). The port's signature is
  `set_valuestring(&mut Value, Option<&[u8]>)`, so the target is exclusively
  borrowed for the call and the replacement cannot be a view into it — the
  aliasing is a *compile error*, not a runtime check. Invisible to the
  differential because the C's answer to it is undefined behavior, so the `set`
  mode deliberately never builds the state (LESSONS #36: a differential can only
  compare where the C has an answer).

- **`cJSON_SetNumberHelper`'s missing NULL check (cJSON.c:385).** Only the
  `cJSON_SetNumberValue` MACRO guards the argument; the exported function
  dereferences `object` immediately, so a caller who links against the symbol —
  it is `CJSON_PUBLIC` and declared in the public header — gets a NULL-deref.
  `&mut Value` has no null state. Also invisible to the differential, and for
  the same reason: the C's answer is a segfault, not a value, so the `set` mode
  calls it only for a target that exists.

- **`cJSON_SetValuestring`'s length branch.** `strlen(new) <= strlen(old)` reuses
  the existing allocation and the else-branch allocates a fresh one, but both
  leave `valuestring` equal to the new C string and both return it, so the two
  paths are indistinguishable from outside. The `set` mode crosses the branch in
  both directions (its `s2` node's old text is the caller-controlled key) and
  says so here rather than letting "the matrix covers both sides" imply the
  differential can tell them apart. The port has one path: replace the owned
  `Vec<u8>`.

- **`cJSON_DetachItemViaPointer`'s missing membership check.** The C takes
  `(parent, item)` and never verifies that `item` is a child of `parent`; from
  two valid public-API pointers that yields a NULL-pointer WRITE and a silent
  cross-document corruption (MUTATION-API-SPIKE.md H1, three committed
  reproducers). The port has no analogue and API-COVERAGE.md marks the symbol
  **out-of-scope**: `Value` is an owned tree with no parent pointers and no
  sibling list, so a child cannot be held while its parent is separately named.
  Invisible to the differential because the state cannot be *reached* from the
  port's API to be compared — the `seq` mode's ops are index/key based, which
  makes the offending sequence unspellable rather than merely untested.

  The four entry points that reach it in the C **are** ported, and they are safe
  there for a reason worth recording: each looks the item up inside the parent
  first, so the absent check is satisfied by construction. Probed rather than
  assumed (`spikes/detach_relink.c`).

- **The detached node's ownership.** `cJSON_Detach*` hands back a pointer the
  caller must `cJSON_Delete`, and forgetting to is a leak the compiler cannot
  see; `cJSON_DeleteItemFrom*` is literally `cJSON_Delete(cJSON_Detach…(…))`.
  The port returns an owned `Detached`, so the value is either bound or dropped
  and the leak is not expressible. No output difference, so no ledger row — but
  it is half the reason this family is worth porting.

- **`cJSON_SetValuestring`'s `IsReference` and NULL-`valuestring` guards.** Both
  need a node built by `cJSON_CreateStringReference`, which API-COVERAGE.md
  refuses as out-of-scope (a borrowed pointer whose correctness depends on the
  caller outliving the tree). The port never builds one, so the branches are
  unreachable rather than untested — and the `set` mode does not fake them with
  a hardcoded answer on the Rust side, which would be a control nothing invokes
  (LESSONS #31).

These historical-CVE classes are eliminated by Rust's type system and produce
**no observable divergence**, so they never appear as ledger entries — they are
recorded in `FLAW-SCAN.md` as the port's safety win: use-after-free (#248),
dangling-realloc arbitrary write (#189), out-of-bounds read/write (#230, #338,
a167d9e), NULL-deref (CVE-2024-31755, CVE-2023-50471/50472). The port reproduces
the same *observable* behavior (same output, same accept/reject) by a *safe*
construction; the differential confirms the behavior matches, and the safety is
the invisible dividend.
