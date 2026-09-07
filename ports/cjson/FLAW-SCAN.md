# Phase 0 — C-flaw inventory (cJSON v1.7.18)

> **Scope grows with the port.** Phase 0 covered `cJSON.c`/`cJSON.h` (17 sinks).
> `cJSON_Utils.c` joined at module 9, taking the scan to **25**; its 8 sinks are
> triaged in their own section below. Any future C file added to `c/` must be
> triaged here — `check.sh` re-runs the scan over all of `c/` every run so a new
> source cannot arrive un-triaged (LESSONS #31).

Two inputs feed this: the kit's `scan_c_flaws.py` (grep-able sinks) **and** the
upstream `CHANGELOG.md` (the historical CVE/security record). They cover different
classes, and the gap between them is itself the most important Phase-0 finding.

## The scanner is the wrong tool for cJSON's real bug class — on purpose

`scan_c_flaws.py cJSON.c cJSON.h` → **17 hits, all `unbounded-copy` (CWE-120)**.
Every one is a `memcpy`/`strcpy`/`sprintf` sink. But **cJSON's actual CVE history
is not a copy-sink class** — it is recursion depth, out-of-bounds *reads* on
truncated input, integer overflow in buffer growth, use-after-free on string
aliasing, and NULL-deref. The grep scanner cannot see any of those (they are
arithmetic/lifetime/logic bugs, not literal calls to a dangerous function). This
mirrors the adler32 lesson exactly: *the flaw scanner finds the sinks; the
differential + fuzz gates find the arithmetic/logic bugs; they divide labor.* For
cJSON the **fuzz gate is the load-bearing one**, and Phase 2 must seed its corpus
with regression inputs for every historical CVE below.

## Historical CVE / security record (from CHANGELOG.md — the port MUST preserve every fix)

cJSON v1.7.18 is **hardened** C: it already contains a decade of security fixes.
So unlike adler32 (whose C had a *live* bug the port fixed), here the port's job
is to **not silently drop a guard** the C earned in blood — and, where Rust can,
to make the guarantee *structural* instead of a manual check that a future edit
could remove.

| Ref | Class | C's fix | What the Rust port must do |
|---|---|---|---|
| CVE-2024-31755 | NULL-deref | `cJSON_SetValuestring` NULL-checks its arg (cJSON.c:413) | `Option<&str>` — unrepresentable, structural |
| CVE-2023-50472 | NULL-deref | NULL check in `SetValuestring` | same |
| CVE-2023-50471 | NULL-deref | NULL check in `cJSON_InsertItemInArray` | `Option`/typed index — structural |
| #852 | heap buffer overflow | bounds fix | bounds-checked slices — structural |
| #338 | `cJSON_Minify` OOB **read+write** | rewrote minify with a bounded state machine (cJSON.c:2839–2900) | slice iteration, no raw `char*` walk — structural |
| #248 | **use-after-free** on `AddItemToObject` string aliasing | detects the alias | ownership/borrow — the whole class is unrepresentable |
| #230 | off-by-one **OOB write** + buffered-print errors | index fix | bounds-checked — structural |
| #189 | `realloc` fail → dangling pointer → **arbitrary write** | checks realloc result | `Vec` growth cannot return a dangling pointer — structural |
| a167d9e | `parse_string` reading buffer overflow | added end checks | slice bounds — structural |
| (design) | **stack overflow** via deep nesting | `CJSON_NESTING_LIMIT = 1000` (cJSON.h:137), enforced at cJSON.c:1459 (array) & 1619 (object) | **MUST replicate the depth guard** — Rust recursion stack-overflows too; this is the one guard Rust does *not* give for free |
| ensure/2683d4d | integer overflow in buffer growth | overflow check before `realloc` | checked arithmetic / `usize` — structural, but preserve the intent |

## The 17 copy-sink hits — triage

All 17 become safe-by-construction in Rust (`String`, `Vec<u8>`, `format!`,
slice copies with checked lengths). Grouped by why the C is (or isn't) currently safe:

- **Fixed-size `number_buffer[26]` sprintf (cJSON.c:571,575,580,586)** — `print_number`
  prints a double into a 26-byte stack buffer with `%1.17g`. Safe in C *by
  manual buffer-sizing* (a `%1.17g` double fits). Rust: `format!` into a `String`;
  the size reasoning disappears. **Log as divergence** only if output bytes differ.
- **String-literal `strcpy`/`sprintf` (cJSON.c:127,933,1397,1406,1415,1020)** —
  `"null"`, `"true"`, `"false"`, `"\"\""`, the `u%04x` escape, the version string.
  Bounded by construction; benign. Rust: string literals / `write!`.
- **Computed-length `memcpy` (cJSON.c:204,523,974,1237,1435,1967)** — the
  interesting ones: buffer growth (`ensure`), string copy-out, `create_reference`
  struct copy. Each is safe in C *because* a preceding length/overflow check ran
  (the #189/#230/ensure fixes). Rust: bounds-checked slice copy — the check is the
  language's, not the programmer's.
- **`cJSON_SetValuestring` `strcpy` (cJSON.c:418)** — the CVE-2024-31755 site;
  copies only when `strlen(new) <= strlen(old)`. Correct in C *given the NULL
  checks above it*. Rust: `Option<&str>` + owned `String` reassignment; both the
  length dance and the NULL check vanish.

**None of the 17 is a live bug in v1.7.18.** Each is a place where C safety rests
on a manual invariant; the port's value is making that invariant structural.
Every one that produces byte-identical output needs **no** `DIVERGENCES.md` entry;
any that changes output (e.g. number formatting) gets one.

## The 8 `cJSON_Utils.c` copy-sink hits — triage (added 2026-08-30, module 9)

**Why these arrived late, and the gap that let them:** this document was written at
Phase 0 over `cJSON.c`/`cJSON.h` only. `cJSON_Utils.c` entered the port's scope at
**module 9**, and the scan was never re-run, so its 8 sinks sat un-triaged while
the module cleared all six gates — the scanner said 25, this file said 17, and no
gate compared the two. Fixed structurally: `check.sh` now re-runs the flaw scan
over **all** of `c/` on every gate run, and `control-coverage` fails if it doesn't
(LESSONS #31).

- **`cJSONUtils_strdup` `memcpy` (:77)** — `length = strlen(s) + 1`, `malloc(length)`,
  `memcpy(…, length)`. Exact fit; benign. Rust: `Vec<u8>` clone.
- **Pointer-building `sprintf`/`strcat` (:234, :245)** —
  `cJSONUtils_FindPointerFromObjectTo`. `malloc(strlen(target) + 20 + sizeof("/"))`
  against a write of `/` + ≤20 digits + target + NUL; and
  `malloc(strlen(target) + pointer_encoded_length(key) + 2)` against
  `/` + encoded key + target + NUL. Both are **exact-fit** manual sizing (the `20`
  is `log10(2^64)`), correct but with zero slack — one more byte in the format
  string would be an overflow. Not reached by the port's surface anyway
  (`FindPointerFromObjectTo` is not ported).
- **Patch-path `sprintf` (:1122, :1188, :1203, :1248)** — `create_patches` /
  `compose_patch`, the code module 9 **does** port. Same exact-fit pattern:
  `malloc(path_len + suffix_len + sizeof("/"))` for `"%s/"` + encoded suffix, and
  `malloc(strlen(path) + 20 + sizeof("/"))` for `"%s/%lu"`. The `index > ULONG_MAX`
  guards beside them are dead on LP64 (the source says so) — the real bound is the
  hand-computed `20`.
- **`replace_item_in_object` struct `memcpy` (:804)** — `sizeof(cJSON)` fixed-size
  copy; benign.

**None of the 8 is a live bug either**, but four of them sit in ported code and all
rely on hand-computed exact-fit lengths. The Rust port builds every pointer path by
appending to a `Vec<u8>` (`encode_pointer_segment`, `create_patches`), so the
sizing arithmetic — and the CWE-120 class with it — does not exist there. No
`DIVERGENCES.md` entry: the generated paths are byte-identical (the differential
and the 25k-iteration `genpatch` fuzz both confirm).

## Live defects found by PROBING, not by the scanner (added 2026-09-05, extended 2026-09-07)

The scanner greps for copy sinks. Only one of the five below is a copy sink at
all — and it is one the scanner **did** report, as line 418, and this document
triaged as benign in 2026-08 (see the `cJSON_SetValuestring` bullet under "The 17
copy-sink hits" above, which reasoned about the length check and stopped there).
None was found by reading; each turned up when a module put the relevant entry
point on the compared contract, or when its spike ran the C under sanitizers.
Recorded here because this file is the port's flaw record, and a flaw record that
only contains what a regex can see is measuring the regex.

| # | Where | Class | Status |
|---|---|---|---|
| L1 | `cJSON_CreateNumber` (cJSON.c:2471) | **CWE-758**, reliance on undefined behavior: `(int)num` on a NaN. C17 6.3.1.4p1 — and target-dependent in fact (INT_MIN on x86-64, 0 on AArch64), not merely in theory | **Found + ledgered**, module 11. Port takes the defined answer (0). `DIVERGENCES.md create-number-nan-valueint`, 5 pinned rows |
| L2 | `cJSON_DetachItemViaPointer` (cJSON.c:2231) | **CWE-476**, NULL-pointer WRITE. No check that `item` is a child of `parent`; an empty parent plus a last-of-another-list item writes through `parent->child` | **Found + reproduced** (`spikes/detach_null_write.c`, ASan SEGV). Not yet ported — see `MUTATION-API-SPIKE.md` |
| L3 | same | **CWE-787**-adjacent silent state corruption: the same write splices a pointer from one document's list into another's last-item cache. No error; the damage appears on a *later, unrelated* call, which then appends to the wrong document | **Found + reproduced** (`spikes/detach_cross_document.c`, `detach_corruption_cashes_in.c`). Drives the mutation module's design |
| L4 | `cJSON_SetValuestring` (cJSON.c:418) | **CWE-758**, reliance on undefined behavior: an OVERLAPPING `strcpy`. The "new is no longer than old" fast path is `strcpy(object->valuestring, valuestring)` with nothing stopping `valuestring` pointing into that same buffer — `cJSON_SetValuestring(item, item->valuestring + 2)` is a plausible in-place prefix strip, and C17 7.24.2.3 makes overlapping copies undefined | **Found + reproduced** (`spikes/setvaluestring_alias.c`, ASan `strcpy-param-overlap`). Port ships module 12: the signature takes `&mut Value` plus a separate slice, so the aliasing is a compile error. `DIVERGENCES.md`, "Structural eliminations" |
| L5 | `cJSON_SetNumberHelper` (cJSON.c:384) | **CWE-843**, type confusion: writes `valueint`/`valuedouble` with **no type check**, leaving a `cJSON_String` node that carries a number. Public struct fields, so it is observable — and it outlives the call. Plus **CWE-476**: the exported symbol has no NULL check (only the `cJSON_SetNumberValue` macro does), and **CWE-758** again, the same `(int)NaN` cast as L1 | **Found + ledgered**, module 12. Port makes the state unrepresentable. `DIVERGENCES.md set-*-type-confusion` (6 pinned rows) and `set-nan-*` (4 pinned rows); the NULL-deref is a structural elimination |

L2–L5 are in a currently-shipping MIT library. They are characterized here solely
to keep them out of the port (the Prime Directive's *"do not faithfully
re-implement a vulnerability"*). Nothing has been reported anywhere; see
`MUTATION-API-SPIKE.md` §6 — that is a deliberate decision to leave to the repo's
owner, not an oversight.

**L4 is the one that should sting.** It is not a class the scanner is blind to —
line 418 is *in* the 17 hits above, and this document triaged it in 2026-08 as
"correct in C *given the NULL checks above it*". That conclusion was about buffer
sizing, and it was right about buffer sizing; it simply never asked what happens
if the two pointers are the same object. Reading a sink and concluding "safe"
answers the question you thought to ask. Running it under ASan answers the one
you did not.

## Net Phase-0 security posture

Phase 0 concluded **preserve-and-harden, not fix-a-live-bug**, and that was an
accurate reading *of what Phase 0 could see*. Four modules later it is no longer
true: L1, L4 and L5 are live UB / type-confusion defects the port deliberately
diverges from or designs out, and L2/L3 are live memory-safety defects in code
the port has not reached yet. The correction matters more than the conclusion
did — **"no live bugs" was a statement about the scan's reach, and it survived as
a statement about the library** until something actually exercised the code.

Note the trend, because it is the argument for keeping this section: the count
went 0 → 3 → 5, and every increase came from a module putting more C on the
compared contract or running it under a sanitizer. Nothing about the library
changed. The number tracks how much of it has been *executed*, which is the only
honest thing a flaw record can be a count of.

The threat model (`THREAT-MODEL.md`) and the port plan (`PORT-PLAN.md`) remain
built around the two guards Rust does **not** give for free — **recursion depth**
(must be replicated) and **output byte-fidelity** (the oracle's job) — and the
several classes it **does** eliminate structurally (UAF, dangling-realloc, OOB
read/write, NULL-deref). L2 and L3 fall squarely in that last group, which is why
the port's answer to them is structural rather than a patch.
