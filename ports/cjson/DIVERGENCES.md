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

- [x] `scalar-parent-child` — **the non-container parent, now on the compared
  contract.** cJSON's `add_item_to_array` (cJSON.c:1973) guards exactly three
  things: a NULL item, a NULL parent, and self-reference. It never asks whether
  the parent is a container, and `add_item_to_object` only adds a NULL-key
  guard before delegating to it. So every public `Add*` entry point will hang a
  child off a number, a string, a bool, a null or a raw node, and will give an
  OBJECT a member whose key is NULL.

  The port answers **false**. `Value::Array(Vec<Value>)` is the only variant
  with anywhere to put a child and a `Value::Object` entry always has a key, so
  the malformed tree is **unrepresentable**, not merely rejected. Reproducing
  it would mean giving every variant a child list purely so the port could
  build documents whose printed form misrepresents them — a Prime Directive
  refusal. Executed evidence: `SCALAR-PARENT-SPIKE.md`, `spikes/scalar_parent.c`,
  clean under ASan+UBSan+LSan (the class is behavioural, so sanitizers cannot
  catch it; only a differential can).

  **Why it took four attempts to gate.** The port's behaviour has been correct
  since module 6; what was missing was evidence. All three of the port's
  existing comparison surfaces are blind to this class — `print` ignores a
  child hung off a non-container (a number still prints `7`) and drops a key
  stored on an array element; `cJSON_Compare` reports a malformed node EQUAL to
  a clean one because it never examines a non-container's children; and
  `cJSON_Duplicate` copies the hung child so a dup round-trip matches too. A
  descriptor built on printed bytes returns MATCH on every case in the list
  below. The `parent` mode therefore reports the **container view**
  (`cJSON_GetArraySize`, `cJSON_GetArrayItem`) and the two object lookups
  **separately** — LESSONS #39's rule applied to a whole module rather than one
  op: name the operation that CONSUMES the state no output depends on.

  The 12 rows are chosen to pin each distinct reachable SHAPE, not to enumerate
  the 6 kinds × 8 ops cross product: once one scalar kind is pinned the other
  five assert the same fact, and forty more rows would make a real change
  harder to read rather than better evidenced.

- [x] `parent-num-add` [sha256:df146b678bcf]: a child hung off a **number**.
  The C answers `rc=1`, `size=1`, `item0=99`; the port answers `rc=0`, `size=0`,
  `item0=-`. Note `print` MATCHES on both sides (`7`), which is exactly why this
  survived fourteen modules undetected.
- [x] `parent-str-add` [sha256:d7af1c0f0c31]: same, onto a **string**.
- [x] `parent-true-add` [sha256:e507832eb50d]: same, onto **true**.
- [x] `parent-false-add` [sha256:8f6ef8a9ab4e]: same, onto **false**.
- [x] `parent-null-add` [sha256:7dbfc0b37e82]: same, onto **null**.
- [x] `parent-raw-add` [sha256:bd84259ce24e]: same, onto a **raw** node.
- [x] `parent-obj-add-array-item` [sha256:cb6d4232b823]: **the NULL-keyed
  member, and the lookup it breaks.** `cJSON_AddItemToArray` on an object
  produces `{"pre":1,"":99,"post":2}` — which *prints* as an ordinary object
  with an empty-string key, so parsing that text back gives a document where
  `""` is findable while the original's is not. Worse, `post` is an ordinary
  member added AFTER the malformed one and
  `cJSON_GetObjectItemCaseSensitive("post")` can no longer find it: the
  case-sensitive loop tests `current_element->string != NULL` in its condition
  (cJSON.c:1910), so the walk STOPS at the NULL key and never reaches anything
  behind it. One malformed member is a denial-of-lookup for the entire
  remainder of the object. `cJSON_GetObjectItem` walks past it —
  `case_insensitive_strcmp` returns 1 for NULL (cJSON.c:135) — so the two
  functions differ in *reachability*, not just case handling. The descriptor
  shows it as `post=1/0` against the port's `post=1/1`.
- [x] `parent-arr-add-keyed` [sha256:2de1a847ceda]: `cJSON_AddItemToObject` on
  an **array** stores a key `print_array` never emits, so a print round-trip
  silently loses it.
- [x] `parent-num-add-true` [sha256:2cf3b0278f18]: the same class reached
  through the `cJSON_Add*ToObject` helper family rather than the two primitives
  — pinned so the ledger does not imply only `AddItemTo*` is affected.
- [x] `parent-num-add-number` [sha256:a3559170e3c9]: same, `cJSON_AddNumberToObject`.
- [x] `parent-num-add-cs` [sha256:1bc1c40577a3]: same through
  `cJSON_AddItemToObjectCS`, whose key is BORROWED rather than copied.
- [x] `parent-doc-scalar` [sha256:a18acecaf683]: the same class reached with
  the target chosen by the **document** rather than by the case — the shape a
  fuzzer finds on its own.

  **What deliberately still MATCHES**, and is in the matrix to prove the
  divergence is no wider than claimed: every container-appropriate op
  (`arr`+`a`, `obj`+`o`/`ocs`/`t`/`f`/`z`/`m`/`s`), the unknown-op and
  unparseable-document refusals, and — the useful one — a member genuinely
  keyed `""`, which IS findable by `""` (`empty=1/1`) where the NULL-keyed
  member is not (`empty=0/0`). Both print as `""`. The `cmp` and `dupsz` fields
  are carried for the same reason: `Compare` and `Duplicate` are blind here and
  a ledger that hid that would be claiming more than the run shows.

  **The history, kept because it is the argument for the module.**
  `dom-construct` declined this class (no mode built a non-container parent).
  `dom-mutate-remove` came within one line of dragging it in and declined: its
  `seq` mode needs an *append* op, and an append whose target is fuzzer-chosen
  will sooner or later name a scalar — so `app` refuses any non-array target on
  both sides. `dom-mutate-place` declined it twice more, giving `ins` and `rep`
  the same restriction, while deliberately NOT restricting `ro`/`ros`
  (`cJSON_ReplaceItemInObject*`), every failure of which is representable on
  both sides. Each refusal was written into `cjson_modes.h`, into `modes::seq`
  and here, because an unstated refusal is indistinguishable from an oversight.
  Three routings around one class is what scheduled this increment.

- [x] `opts-prealloc-one-short` [sha256:9c6fa00bf415]: **a failed
  `cJSON_PrintPreallocated` leaves a silently truncated document in the
  caller's buffer** (CWE-252, unchecked return value, made exploitable by the
  C's choice of failure state). cJSON.c:1305 returns `print_value`'s verdict and
  nothing else; every writer inside it terminates its own fragment, so a buffer
  one byte too small comes back holding
  `{"a":[1,2],"b":"xy` + `\0` — a **NUL-terminated, well-formed-looking, shorter
  render**. A caller that ignores the `cJSON_bool` cannot distinguish it from a
  successful print of a smaller document; nothing in the bytes says "truncated".
  The port writes **nothing** on failure, so the `bool` is the only channel the
  result can arrive on and a partial render can never masquerade as a whole one.

  The buffer size here is `strlen + 1`, which is the one a caller sizing "the
  string and its terminator" would pick — `ensure` reserves a NUL slot *on top
  of* `needed`, so the real requirement is `strlen + 2` (see
  `crates/core/src/print.rs`). That makes this failure the *likely* one, not an
  exotic one.

  Measured, not asserted: the `opts` mode reports the buffer's bytes as
  `ppabuf`, so the divergence is in the compared output rather than a claim
  about code nobody runs (LESSONS #31/#40). Differential FUZZING uses the
  corrected reference (`oracle/make_fixed_core.py` zeroes the buffer on the
  failure path, which given the driver zeroes it first is exactly "untouched"),
  because every buffer length below the boundary triggers this — a
  predicate-defined class with no finite fingerprint set (LESSONS #28).
- [x] `opts-prealloc-tiny` [sha256:b2e6af498113]: same defect, buffer of 3 —
  the truncation is `{` and reads back as a plausible fragment start.
- [x] `opts-prealloc-mid` [sha256:45a9963c88c8]: same defect, buffer of 10,
  truncating mid-array (`{"a":[1,`).
- [x] `opts-prealloc-fmt-short` [sha256:813a147126fa]: same defect on a
  FORMATTED print, whose boundary is a different number (the formatted bytes'
  length plus two) — pinned so the ledger does not imply the unformatted
  boundary is the only one.
- [x] `opts-prealloc-nested-short` [sha256:99f4747d2560]: same defect where the
  binding `ensure` is a nested object's `depth + 1` close, i.e. reached through
  a different call site than the four above.

  Not every short buffer diverges, and that is worth stating: a buffer too small
  for the FIRST `ensure` fails before anything is written, so the C leaves it
  untouched too and the differential reports MATCH (`opts-prealloc-scalar-short`,
  `null` into 5 bytes). The divergence is exactly "the C got partway".

Beyond those three JSON-Patch escape fixes, the NaN cast, and the
preallocated-print partial write above, every ported module matches the C
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

- **`cJSON_PrintPreallocated`'s `buffer == NULL` and `length < 0` guards
  (cJSON.c:1309).** Two of the function's three refusals exist only because C
  cannot state "a writable region of n bytes" in the type system. The port takes
  `&mut [u8]`: a null slice cannot be spelled and a length cannot be negative, so
  both branches have no code to live in. The negative length is still *answered*
  — by the `opts` mode on both sides, which returns false without calling the
  core — because the driver does accept an `int` from stdin and has to decide;
  putting the guard in the core instead would be a constant no path reaches
  (LESSONS #31). The NULL buffer has no spelling at any layer and is therefore
  not exercised at all, which is recorded here rather than left to look like an
  oversight.

- **`cJSON_ParseWithLengthOpts`' unchecked `(value, buffer_length)` pair
  (cJSON.c:1104).** Exactly the typed-array constructors' hazard on the parse
  side: a `buffer_length` larger than the allocation is an out-of-bounds read
  the library cannot detect, and it is the entry point's only memory-safety
  hazard. The port takes a slice, so the pair cannot disagree. Invisible to the
  differential by construction — exercising the mismatch makes the C oracle
  undefined, so there is no defined behavior to compare against (LESSONS #36).

- **`cJSON_PrintBuffered(item, 0, fmt)` depends on `malloc(0)`
  (cJSON.c:1281).** A zero prebuffer allocates zero bytes and the C returns NULL
  if the allocator does — so the function's answer for `prebuffer == 0` is
  *platform-dependent*. glibc returns a unique non-NULL pointer, so the oracle
  on this host succeeds; the port has no allocation to fail and succeeds
  everywhere. On this oracle the two agree, which is why this is not a ledgered
  divergence: a ledger row that never diverges is stale by construction and the
  gate would flag it. It is recorded because "the differential shows no
  divergence" must not be misread as "the two are the same function".

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

- **`cJSON_ReplaceItemViaPointer`'s missing membership check.** The same
  unchecked `(parent, item)` contract as its Detach twin, and materially worse:
  after relinking it calls `cJSON_Delete(item)`, so passing an item that belongs
  to a different parent frees a node that parent still links to — a
  use-after-free primitive rather than a wrong answer (MUTATION-API-SPIKE.md H2).
  `Value` is an owned tree with no parent pointers, so a caller cannot name an
  item and a different parent at the same time; the state is a compile error,
  not a runtime check. API-COVERAGE.md lists the symbol as **out-of-scope**, and
  the four entry points that reach it in the C (`ReplaceItemIn{Array,Object,
  ObjectCaseSensitive}`, and `InsertItemInArray` for the insert half) ARE ported
  — they are safe there because each looks the item up inside the parent first.

- **`cJSON_ReplaceItemInObject` renaming a node it then fails to place.**
  `replace_item_in_object` frees the replacement's `->string` and strdups the
  lookup key into it BEFORE the lookup runs, so a call that returns false has
  already overwritten a field of a node the caller still owns (probed;
  `spikes/place_relink.c`). The port takes the replacement **by value**, so
  after a failed call there is no caller-visible node left to have been mutated.
  Invisible to the differential for that exact reason: the `seq` mode has no
  handle to inspect afterwards, and inventing one would mean modelling a state
  the port cannot enter.

- **Insert/replace ownership on the failure path.**
  `cJSON_InsertItemInArray` and `cJSON_ReplaceItemIn*` adopt the new node only
  when they SUCCEED; on a negative index, a NULL item, a missing key or a
  non-container parent the caller is still responsible for freeing it. That rule
  is nowhere in the header, and forgetting it leaks — which is how it was found,
  in this module's own probe program, named by LeakSanitizer. The port's
  functions take the value and drop it when the call fails, so there is no rule
  to remember. It changes no output, so no differential can see it; what checks
  the C side of it now is `check.sh` step 4a (LESSONS #40).

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
