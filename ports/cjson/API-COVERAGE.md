# API coverage — every exported symbol must be accounted for

`harnesses/api-coverage/check_api.py` reads the tables below and the C headers,
and **fails the gate if an exported symbol has no row** (or a row has drifted
from a symbol the headers no longer export). Every row is one of:

| Status | Means |
|---|---|
| `ported` | a driver mode or ABI vector calls it, so the differential compares it |
| `unported` | not done yet — needs a written note saying what is missing |
| `out-of-scope` | deliberately never to be ported — needs a written reason |

`unported` is counted against a ceiling this file states in plain text (below).
More than the ceiling fails (the ungated surface grew); fewer fails too (ratchet
it down and lock the progress in).

## The headline number, stated before the tables

**92 exported symbols across both headers: 82 ported, 10 out-of-scope, 0
unported.** This port covers cJSON_Utils completely and the whole of the base
library's parse / print / minify / query / build / **accessor** /
**constructor** / **setter** / **removal** / **placement** / **options**
surface. The only symbols not ported are the 10 recorded below as deliberate
refusals under the Prime Directive, each with the reason written down.

The ratchet reaches zero here. That is a claim about COVERAGE, not about
completeness of verification: every exported symbol is now on a compared
contract, which is exactly what this table was built to measure and no more.
[Corrected 2026-10-10: not every one yet. Five `*CaseSensitive` utils rows name
driver modes that no case drives (see the note under that table), and
`cJSON_Parse` and `cJSON_GetErrorPtr` are compared only transitively; each of
those rows says so in its own cell.] [Closed 2026-10-17: all seven are now
called by a driver mode or ABI vector of their own. Putting them there found
two C defects the port now fixes (`utils-cs-detach-*`, the stale
`cJSON_GetErrorPtr` after `cJSON_Parse(NULL)`), one undecided port behaviour
now ledgered as a fix (`utils-add-dup-key*`), and four port bugs: the
cdylib's `cJSON_Parse` parsed one byte short, `compare_json` checked lengths
before walking, `genmerge` compared clones, and `cJSON_GetErrorPtr` was not
exported at all. Details under each table.]
The gate stays wired at 0 so the next symbol added to the header, or the next
module that quietly drops one, fails loudly instead of passing.

api-coverage: max-unported = 0

Why it exists (LESSONS #34, mechanizing #26): module 9 (`cJSON_Utils`) shipped
**"DONE" through all six green gates with two of these 14 symbols never ported and
never gated** — `cJSONUtils_FindPointerFromObjectTo` and
`cJSONUtils_AddPatchToArray`. LESSONS #26 already required checking driver modes
against the public API; it was prose in a playbook, so it did not fire. Both are
now ported and on the compared contract (`findptr` / `addpatch` driver modes,
11 matrix cases, 12 probes).

A note on how the gap was almost mis-measured: a bare identifier grep of the
header also reported `cJSONUtils_AtomicApplyPatches` as missing. It is a
**commented-out suggestion** inside a `/* */` block with no implementation and no
`CJSON_PUBLIC` — not API at all. The checker therefore strips C comments and
requires the export macro, and pins that case in its self-test.

## `c/cJSON_Utils.h` — 14 exported symbols

| Symbol | Status | Where it is gated |
|---|---|---|
| `cJSONUtils_GetPointer` | ported | `utils::get_pointer` — driver mode `ptr` |
| `cJSONUtils_GetPointerCaseSensitive` | ported | same, `cs=true` — driver mode `ptr-cs`; its cases pair each input with the case-insensitive mode (gap closed 2026-10-17, below the table) |
| `cJSONUtils_ApplyPatches` | ported | `utils::apply_patches` — driver mode `patch` |
| `cJSONUtils_ApplyPatchesCaseSensitive` | ported | same, `cs=true` — driver mode `patch-cs`; its cases pair each input with the case-insensitive mode (gap closed 2026-10-17, below the table) |
| `cJSONUtils_MergePatch` | ported | `utils::merge_patch` — driver mode `merge` |
| `cJSONUtils_MergePatchCaseSensitive` | ported | same, `cs=true` — driver mode `merge-cs`; its cases pair each input with the case-insensitive mode (gap closed 2026-10-17, below the table) |
| `cJSONUtils_GenerateMergePatch` | ported | `utils::generate_merge_patch` — driver mode `genmerge` |
| `cJSONUtils_GenerateMergePatchCaseSensitive` | ported | same, `cs=true` — driver mode `genmerge-cs`; its cases pair each input with the case-insensitive mode (gap closed 2026-10-17, below the table) |
| `cJSONUtils_GeneratePatches` | ported | `utils::create_patches` — driver mode `genpatch` |
| `cJSONUtils_GeneratePatchesCaseSensitive` | ported | same, `cs=true` — driver mode `genpatch-cs`; its cases pair each input with the case-insensitive mode (gap closed 2026-10-17, below the table) |
| `cJSONUtils_SortObject` | ported | `utils::sort_object` — driver mode `sort` |
| `cJSONUtils_SortObjectCaseSensitive` | ported | same, `cs=true` — driver mode `sort-cs` |
| `cJSONUtils_FindPointerFromObjectTo` | ported | `utils::find_pointer_from_object_to` — driver mode `findptr` |
| `cJSONUtils_AddPatchToArray` | ported | `utils::add_patch_to_array` — driver mode `addpatch` |

**Open gap (found 2026-10-10), closed 2026-10-17.** Both drivers implemented
`ptr-cs`, `patch-cs`, `merge-cs`, `genmerge-cs` and `genpatch-cs` (and
`findptr-cs`), but no matrix case, probe, holdout vector or `check.sh` diff-fuzz
run invoked any of them — `sort-cs` was the only `-cs` mode anything drove.
Now every input added for them goes in TWICE, under the case-insensitive mode
and its `-cs` twin, so the flag is pinned in both directions: 37 inputs, 74
matrix cases and 74 probes, each with a note naming what it tells apart.
`check.sh` fuzzes all six `-cs` modes (and `findptr`/`addpatch`, which the gate
had not fuzzed either), and `mutants.toml` holds one wrong version of each
flag's rule; every one is killed by the cases.

What driving them found, in the order it was found:

* **`utils-cs-detach-*` — a C defect, now a ledgered fix.** The first `patch-cs`
  input with a differently-cased key diverged: `detach_path` ends in the
  case-INsensitive `cJSON_DetachItemFromObject` whatever the flag, so
  `ApplyPatchesCaseSensitive`'s `remove /A` deletes `a`. The port had always
  detached case-sensitively — an unexamined divergence since module 9.
* **`compare_json` checked lengths first — a port bug.** The C walks the pairs
  (recursing, and so sorting nested objects in place) BEFORE it notices a
  leftover; the port returned early and skipped the sorts. Visible through
  `patch`'s `test` (which prints the document) in both modes.
* **`genmerge` compared clones — a port bug.** The C's `compare_json` sorts the
  paired children in place and the recursion sorts them again; `sort_list` is
  unstable (a tie takes the second run), so tied keys swap twice in the C and
  once in the port. Found by the first `genmerge-cs` sweep; present in
  `genmerge` too.
* **`utils-add-dup-key*` — undecided port behaviour, now a ledgered fix.** The
  port's `add` deletes every member its key names; the C deletes one, leaving
  a duplicated key's old value first. Found once the seeds carried duplicate
  keys; kept and ledgered because the C's answer lets a duplicated key defeat
  a patch that enforces a field.

### High-budget sweep on the `-cs` modes (LESSONS #33 + #42), 2026-10-17

Run on the FINAL binary — after the three port fixes above — with the matrix
that carries the new case-pair and duplicate-key seeds:

| Mode | Oracle | Seeds | Iterations each | Findings |
|---|---|---|---|---|
| `ptr-cs` | pristine | 1 / 2 / 3 | 20 000 | 0 |
| `findptr-cs` | pristine | 1 / 2 / 3 | 20 000 | 0 |
| `merge-cs` | pristine | 1 / 2 / 3 | 20 000 | 0 |
| `genmerge-cs` | pristine | 1 / 2 / 3 | 20 000 | 0 |
| `genpatch-cs` | pristine | 1 / 2 / 3 | 20 000 | 0 |
| `patch-cs` | corrected | 1 / 2 / 3 | 20 000 | 0 |
| `genmerge` | pristine | 1 / 2 / 3 | 20 000 | 0 |
| `patch` | corrected | 1 / 2 / 3 | 20 000 | 0 |
| `patch-cs` | **pristine** | 7 | 4 000 | 15, all ledgered |
| `patch` | **pristine** | 11 | 4 000 | 8, all ledgered |

480 000 generated inputs, zero divergences. `genmerge` and `patch` are swept
again because the fixes changed them and the new seeds reach them: the first
`genmerge-cs` sweep, on the binary before the fixes, found 29 distinct
divergences across its three seeds, every one of which matches the C once
`compare_json` walks before it counts and `genmerge` stops comparing clones.

The two pristine rows are the LESSONS #42 control, and they had more to
control than before: the corrected oracle now carries THREE utils corrections.
Every finding was classified mechanically, by building one oracle per
correction and asking which single one makes the C agree with the port:
`patch-cs` — 9 detach, 3 tilde, 3 duplicate-key, 0 outside; `patch` — 4 tilde,
4 duplicate-key, 0 outside (and no detach finding, as it must be: that
correction is a no-op without the flag). Each correction is as wide as its
ledgered class and no wider.

### High-budget sweep on the `parse` mode (LESSONS #33), 2026-10-17

| Mode | Oracle | Seeded from | Seeds | Iterations each | Findings |
|---|---|---|---|---|---|
| `parse` | pristine | `matrix.json` (the 79-vector corpus) | 1 / 2 / 3 | 20 000 | 0 |
| `parse` | pristine | `matrix-opts.json` (BOM, terminator, embedded NUL) | 1 / 2 / 3 | 20 000 | 0 |

120 000 generated inputs, zero divergences. The mode compares the core's
`parse_with_opts` to the C's `cJSON_Parse`; the cdylib's own `cJSON_Parse` —
the one that was one byte short — is compared by the ABI vectors, which the
fuzzer does not drive.

### High-budget sweep on the two new modes (LESSONS #33)

The gate's 2000-iteration diff-fuzz is a regression *floor*, not evidence of
sufficiency — module 9's first "DONE" hid four real divergences that only a
25k-iteration sweep reached. So before calling these two entry points done, the
same sweep was run against the C oracle:

| Mode | Seed | Iterations | Findings |
|---|---|---|---|
| `findptr` | 0 | 25 000 | 0 |
| `findptr` | 12345 | 25 000 | 0 |
| `addpatch` | 0 | 25 000 | 0 |
| `addpatch` | 12345 | 25 000 | 0 |

100 000 generated inputs, zero divergences (executed 2026-08-31). Their input
spaces are small — `findptr` is one pointer plus a document, `addpatch` a fixed
`op`/`path`/`value` triple with no grammar of its own — so 10× the gate budget
across two seeds is a defensible argument here, unlike `patch`, whose two-document
op grammar is what made 2000 insufficient.

## `c/cJSON.h` — 78 exported symbols

This is the hole the previous revision of this file recorded rather than papered
over ("the base library's public surface is still governed by prose"). It is now
wired into the gate. Two notes on getting the *number* right first:

* A first pass reported **80**, including `__declspec` and `__attribute__`. Those
  came from `#define CJSON_PUBLIC(type) __declspec(dllexport) type CJSON_STDCALL`
  — the export macro's own definition, which the declaration pattern reads as a
  declaration. Same class as the commented-out `cJSONUtils_AtomicApplyPatches`
  false positive above; the checker now strips preprocessor lines and pins both
  cases in its self-test.
* "Ported" below means **directly on the compared contract** — a driver mode or
  an ABI vector calls it. When this table was wired, several `unported` rows were
  exercised only *transitively* (cJSON_Utils calls them internally, so the utils
  modes did compare their effect); that is not the same thing, and calling it "ported"
  is precisely the rounding-up this gate exists to stop. Their own contract —
  NULL arguments, type mismatches, detached-item ownership — was never called.
  No `unported` rows remain (see "Unported — 0" below); a `ported` row whose
  symbol is still reached only transitively says so in its own cell.

### Ported — 68

| Symbol | Status | Where it is gated |
|---|---|---|
| `cJSON_Version` | ported | ABI vector `version` (`ffi/vectors.json`) |
| `cJSON_Parse` | ported | driver mode `parse` (16 `parse-*` cases in `matrix-opts.json`, the same as probes) against the core's `parse_with_opts`; and the cdylib export ITSELF through ABI vectors `parse-*` (shim `cjson_parse_seq`). Until 2026-10-17 it was compared only transitively, and the transitive argument held for the core and failed for the cdylib: its `cJSON_Parse` parsed `strlen` bytes where the C parses `strlen + 1`, so a BOM plus one digit (`parse-bom-terminator`) parsed in the C and not in the port. The driver mode alone would not have caught it — it calls the core, which was right — only the ABI vector does |
| `cJSON_ParseWithLength` | ported | cdylib export; shim `cjson_rt`, all ABI `rt-*` vectors |
| `cJSON_Print` | ported | cdylib export; shim `cjson_rt_fmt`, ABI `rt-fmt-*` vectors; driver mode `print` |
| `cJSON_PrintUnformatted` | ported | cdylib export; shim `cjson_rt`, driver mode `print-unformatted` (also `dup`, and every descriptor mode's printed fields) |
| `cJSON_ParseWithOpts` | ported | driver mode `opts`, fields `pwo`/`pwoend` — the parse-end offset on BOTH the success and failure paths |
| `cJSON_ParseWithLengthOpts` | ported | driver mode `opts`, fields `pwl`/`pwlend`; `require_null_terminated` is where the two parsers disagree on identical bytes |
| `cJSON_PrintBuffered` | ported | driver mode `opts`, field `pb`; the `prebuffer < 0` guard is its only observable behavior |
| `cJSON_PrintPreallocated` | ported | driver mode `opts`, fields `ppa`/`ppabuf`/`ppamin` — `ppamin` scans for the smallest buffer that fits, so the whole `ensure` predicate is compared, not one sample of it |
| `cJSON_Delete` | ported | cdylib export; every mode's teardown, checked under miri/ASan |
| `cJSON_Minify` | ported | cdylib export; driver mode `minify`, 4 ABI vectors |
| `cJSON_Duplicate` | ported | cdylib export; driver mode `dup` |
| `cJSON_Compare` | ported | cdylib export; driver modes `dup-eq` (original vs its duplicate) and `parent` (field `cmp`) — both call it with `case_sensitive = 1` only |
| `cJSON_free` | ported | cdylib export; frees every string the print modes return |
| `cJSON_GetErrorPtr` | ported | driver mode `parse` (field `err`: the offset it returns after `cJSON_Parse`) and, since 2026-10-17, a cdylib export compared by ABI vectors `parse-*`/`parse-len-*`/`errptr-*`. The error is STATE, so the shim runs two parses in one call and reads it after each: the reset on success, the length path, and the NULL input — where the C hands back a stale pointer into the previous call's buffer and the port answers NULL (DIVERGENCES.md `errptr-null-input-resets`). Kept per thread, not per process (`errptr-thread-local`, Structural eliminations) |
| `cJSON_GetArraySize` | ported | `cjson_modes_query` — driver mode `query`, 8 ABI vectors |
| `cJSON_GetObjectItemCaseSensitive` | ported | `cjson_modes_query` — driver mode `query` |
| `cJSON_IsInvalid` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsFalse` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsTrue` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsBool` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsNull` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsNumber` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsString` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsArray` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsObject` | ported | `cjson_modes_query` type descriptor |
| `cJSON_IsRaw` | ported | `cjson_modes_query` type descriptor |
| `cJSON_CreateNull` | ported | `cjson_modes_build` — driver mode `build`, 8 ABI vectors |
| `cJSON_CreateTrue` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_CreateNumber` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_CreateString` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_CreateArray` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_CreateObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddItemToArray` | ported | `cjson_modes_build` — driver mode `build`; driver mode `parent` (non-container parent) |
| `cJSON_AddItemToObject` | ported | `cjson_modes_build` — driver mode `build`; driver mode `parent` |
| `cJSON_AddNullToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddBoolToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddNumberToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddStringToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_GetArrayItem` | ported | `dom::get_array_item` — driver mode `access` (`iarr=`) |
| `cJSON_GetObjectItem` | ported | `dom::get_object_item(.., case_sensitive=false)` — driver mode `access` (`kobj=`) |
| `cJSON_HasObjectItem` | ported | `dom::has_object_item` — driver mode `access` (`has=`) |
| `cJSON_GetStringValue` | ported | `dom::get_string_value` — driver mode `access` (`kstr=`/`istr=`) |
| `cJSON_GetNumberValue` | ported | `dom::get_number_value` — driver mode `access` (`knum=`/`inum=`) |

| `cJSON_CreateFalse` | ported | driver mode `construct` (probe `construct-*`, 48 matrix cases) |
| `cJSON_CreateBool` | ported | driver mode `construct` — the count field selects true/false |
| `cJSON_CreateRaw` | ported | driver mode `construct`; raw passthrough pinned by `construct-raw-*` probes (empty / valid JSON / garbage / quotes / NUL-truncated) |
| `cJSON_CreateIntArray` | ported | driver mode `construct`, ints region; guards `count < 0` and NULL pointer both probed |
| `cJSON_CreateFloatArray` | ported | driver mode `construct`, floats region; f32→f64 widening pinned incl. subnormals and infinities |
| `cJSON_CreateDoubleArray` | ported | driver mode `construct`, doubles region; saturation boundaries probed, NaN ledgered |
| `cJSON_CreateStringArray` | ported | driver mode `construct`, NUL-split fields; per-element NUL truncation pinned |
| `cJSON_AddTrueToObject` | ported | driver mode `construct` (`addT` field) |
| `cJSON_AddFalseToObject` | ported | driver mode `construct` (`addF` field) |
| `cJSON_AddRawToObject` | ported | driver mode `construct` (`addR`); the NULL-raw case adds nothing |
| `cJSON_AddObjectToObject` | ported | driver mode `construct` (`addO`) |
| `cJSON_AddArrayToObject` | ported | driver mode `construct` (`addA`) |
| `cJSON_SetValuestring` | ported | driver mode `set` (`sv`/`sv2`/`svnull`/`svnum`); its `object == NULL`, non-string and NULL-replacement guards are each reached by a probe, and both sides of the `strlen(new) <= strlen(old)` branch are crossed. The overlapping-`strcpy` hazard at cJSON.c:418 is designed out, not compared — see DIVERGENCES.md, "Structural eliminations" |
| `cJSON_SetNumberHelper` | ported | driver mode `set` (`sn`/`sn2`); saturation boundaries probed inclusive on both ends, NaN and the missing type check both ledgered. Called only for a non-NULL target: the exported symbol has no NULL check (only the `cJSON_SetNumberValue` macro does), and a segfault is not an answer to compare against |
| `cJSON_DetachItemFromArray` | ported | driver mode `seq`, op `da`; the negative/out-of-range/junk index guards each have a probe, and the not-array-only behaviour (index 0 of an OBJECT takes its first member, key retained) is pinned |
| `cJSON_DeleteItemFromArray` | ported | driver mode `seq`, op `xa`; returns void, so the descriptor compares the container's size and the whole document after the step |
| `cJSON_DetachItemFromObject` | ported | driver mode `seq`, op `do` — the CASE-INSENSITIVE lookup |
| `cJSON_DetachItemFromObjectCaseSensitive` | ported | driver mode `seq`, op `dos`; the case flag is the only difference between the pair and is pinned in both directions |
| `cJSON_DeleteItemFromObject` | ported | driver mode `seq`, op `xo`; a missing key is `cJSON_Delete(NULL)`, probed rather than assumed safe |
| `cJSON_DeleteItemFromObjectCaseSensitive` | ported | driver mode `seq`, op `xos` |
| `cJSON_InsertItemInArray` | ported | driver mode `seq`, op `ins`. Probed: an index PAST THE END is not an error — the C falls through to `add_item_to_array` and appends |
| `cJSON_ReplaceItemInArray` | ported | driver mode `seq`, op `rep`. Unlike insert, an out-of-range index here IS a failure |
| `cJSON_ReplaceItemInObject` | ported | driver mode `seq`, op `ro` (case-INsensitive). Probed: the member's key is rewritten to the LOOKUP string, so replacing `a` in `{"A":1}` leaves `{"a":…}` |
| `cJSON_ReplaceItemInObjectCaseSensitive` | ported | same, op `ros` |

### Out of scope — 10, each a deliberate refusal under the Prime Directive

These are not backlog. The C's contract for each one is *"the caller guarantees a
lifetime the library cannot check"*, and re-exporting that contract would carry
the dangling-pointer class straight into the Rust. The safe core is
`#![forbid(unsafe_code)]`; a node holding a borrowed pointer it must not free
cannot be expressed there without reintroducing exactly what the port removes.

| Symbol | Status | Why |
|---|---|---|
| `cJSON_InitHooks` | out-of-scope | installs a process-global, mutable table of allocator function pointers. Global mutable state plus caller-supplied code pointers, with no way to check that a tree allocated under one hook set is freed under the same one. The port uses Rust's allocator, unconditionally. |
| `cJSON_malloc` | out-of-scope | exists only to pair with `cJSON_InitHooks` (its doc comment says so: "using the malloc/free functions that have been set with cJSON_InitHooks"). With no hook table it is just `malloc`, and exporting it would advertise a hookability the port deliberately does not have. `cJSON_free` IS exported — the ABI must be able to free printed strings — but it frees Rust allocations, not hooked ones. |
| `cJSON_CreateStringReference` | out-of-scope | builds a node whose `valuestring` is a borrowed pointer "so it will not be freed by cJSON_Delete". Correctness depends entirely on the caller outliving the tree. |
| `cJSON_CreateObjectReference` | out-of-scope | same, for a borrowed child list. |
| `cJSON_CreateArrayReference` | out-of-scope | same, for a borrowed child list. |
| `cJSON_AddItemReferenceToArray` | out-of-scope | grafts a node into a second tree without copying; either tree's `cJSON_Delete` can leave the other holding freed memory. |
| `cJSON_AddItemReferenceToObject` | out-of-scope | same. |
| `cJSON_AddItemToObjectCS` | out-of-scope | stores a borrowed key and sets `cJSON_StringIsConst`; cJSON's own header carries a WARNING that callers must test that flag before writing to `item->string`. A safety-critical invariant enforced by a comment is the shape this port exists to delete. |
| `cJSON_DetachItemViaPointer` | out-of-scope | takes `(cJSON *parent, cJSON *item)` and **never checks that `item` is a child of `parent`**. `MUTATION-API-SPIKE.md` H1 reproduces, from two valid public-API pointers, a NULL-pointer WRITE (`spikes/detach_null_write.c`, ASan SEGV at cJSON.c:2231) and a silent cross-document corruption whose damage surfaces on a later, unrelated call (`spikes/detach_cross_document.c`, `detach_corruption_cashes_in.c`). The port cannot express the contract at all: `Value` is an owned tree with no parent pointers and no sibling list, so a child cannot be held while its parent is separately named — the borrow checker refusing to let that state exist IS the answer. A Prime Directive refusal, not backlog; the four entry points that reach it are ported, and they are safe in the C because each looks the item up inside the parent first. |
| `cJSON_ReplaceItemViaPointer` | out-of-scope | the same unchecked `(parent, item)` contract, and worse: after relinking it calls `cJSON_Delete(item)`, so passing an item that belongs to a different parent frees a node that parent still links to — a use-after-free primitive rather than a wrong answer (MUTATION-API-SPIKE.md H2). `Value` has no parent pointers, so the aliasing cannot be spelled. |

### High-budget sweep on the `access` mode (LESSONS #33)

Same discipline as the two utils entry points above — the gate's 2000-iteration
budget is a regression floor, so the sweep was run before calling these five
done:

| Mode | Seed | Iterations | Findings |
|---|---|---|---|
| `access` | 0 | 25 000 | 0 |
| `access` | 12345 | 25 000 | 0 |
| `access` | 777 | 25 000 | 0 |

75 000 generated inputs, zero divergences (executed 2026-09-05). Three seeds
rather than two because this mode's input has **two** grammars the fuzzer can
mutate independently — the `<key>\t<index>` framing and the JSON document — and
the index field alone has to survive junk, a leading `+`, whitespace, INT_MIN
and a 20-digit overflow with both sides normalizing identically. That is a wider
space than `findptr`'s single pointer, and narrower than `patch`'s two-document
op grammar, where 2000 was demonstrably insufficient.

### Unported — 0, against the ceiling declared at the top

Nothing. The last four — the parse/print options surface — landed as module 15
(`entry-opts`, driver mode `opts`); their rows are in the ported table above.

Worth keeping the note the old row carried, because it turned out to be the
substance of the module rather than a caveat. `cJSON.h` tells callers of
`cJSON_PrintPreallocated` to "allocate 5 bytes more than you actually need" —
an admission that the library does not state its own requirement. Measured, it
is `strlen(output) + 2`: `ensure` reserves a NUL slot *on top of* the bytes
asked for, so the obvious `strlen + 1` fails. Both the number and the failure
BEHAVIOR (the C leaves a NUL-terminated truncation behind; the port leaves the
buffer untouched) are now compared rather than described — see DIVERGENCES.md
`opts-prealloc-*`.

### High-budget sweep on the `construct` mode (LESSONS #33)

The gate's 2000-iteration budget is a regression floor, so the sweep was run
before calling these twelve done:

| Mode | Seed | Iterations | Findings |
|---|---|---|---|
| `construct` | 0 | 25 000 | 0 |
| `construct` | 12345 | 25 000 | 0 |
| `construct` | 777 | 25 000 | 0 |

75 000 generated inputs, zero divergences (executed 2026-09-05, against the
**corrected** oracle — see DIVERGENCES.md `construct-nan-*` for why
this mode cannot fuzz against pristine cJSON). Three seeds, matching `access`:
the input carries a `<count>\t<name>\t<raw>` framing *and* a binary payload
that four constructors reinterpret at three widths, so the fuzzer has more
independent grammars to mutate here than anywhere except `patch`. The seed
corpus includes the matrix's `stdin_b64` rows, which carry NaN bit patterns a
UTF-8 seed string could not have spelled at all (LESSONS #36).

### High-budget sweep on the `set` mode (LESSONS #33)

Same discipline again, before calling the two setters done:

| Mode | Seed | Iterations | Findings |
|---|---|---|---|
| `set` | 0 | 25 000 | 0 |
| `set` | 12345 | 25 000 | 0 |
| `set` | 777 | 25 000 | 0 |

75 000 generated inputs, zero divergences (executed 2026-09-07, against the
**corrected** oracle — DIVERGENCES.md `set-nan-*` and
`set-*-type-confusion` are why this mode cannot fuzz against pristine cJSON).
Three seeds because the input has three grammars the fuzzer mutates
independently: a 16-hex-digit `<bits>` field that must normalize identically on
both sides before any `double` exists, a `<key>\t<newstr>` pair the C reads as C
strings, and the JSON document. The seed corpus includes the matrix's
`stdin_b64` rows, whose replacement strings carry an interior NUL and lone
0x80-0xFF bytes — inputs no UTF-8 seed string could spell (LESSONS #36).

### High-budget sweep on the `seq` mode (LESSONS #33)

The widest input space this port has fuzzed, so it gets the largest budget yet:

| Mode | Seed | Iterations | Findings |
|---|---|---|---|
| `seq` | 0 | 25 000 | 0 |
| `seq` | 12345 | 25 000 | 0 |
| `seq` | 777 | 25 000 | 0 |
| `seq` | 31337 | 25 000 | 0 |

100 000 generated inputs, zero divergences (executed 2026-09-07, against the
PRISTINE oracle — this module has no intentional divergence, so every finding
would have been a real port bug). Four seeds rather than three because `seq` has
**three** independently mutable grammars stacked on each other: the JSON
document, the op program (seven opcodes × a selector × an argument, up to eight
steps), and the `<op>\t<sel>\t<arg>` framing itself. It is also the only mode
whose inputs compose — step *n* runs against whatever step *n-1* left behind — so
the reachable state space is larger than the input space, which is precisely the
property the mode exists for and precisely why the gate's 2 000 floor is not an
argument here.

### High-budget sweep on the `seq` mode's PLACEMENT ops (LESSONS #33)

Same discipline as every module before it, run before calling these four done:

| Mode | Seed | Iterations | Findings |
|---|---|---|---|
| `seq` (placement seeds) | 0 | 25 000 | 0 |
| `seq` (placement seeds) | 12345 | 25 000 | 0 |
| `seq` (placement seeds) | 777 | 25 000 | 0 |
| `seq` (placement seeds) | 31337 | 25 000 | 0 |

100 000 generated inputs, zero divergences (executed 2026-09-08, against the
PRISTINE oracle — this surface needs no corrected reference because it diverges
nowhere). Four seeds, matching `dom-mutate-remove`: `seq` stacks three
independently mutable grammars (the document, the `<op>\t<selector>\t<arg>`
framing, and the op sequence itself) and its steps COMPOSE, so the reachable
state space is larger than the input space — an eight-op program reaches trees
no single input describes.

### High-budget sweep on the `opts` mode (LESSONS #33)

Run before calling the last four entry points done:

| Mode | Oracle | Seed | Iterations | Findings |
|---|---|---|---|---|
| `opts` | corrected | 1 | 20 000 | 0 |
| `opts` | corrected | 2 | 20 000 | 0 |
| `opts` | corrected | 3 | 20 000 | 0 |
| `opts` | **pristine** | 7 | 4 000 | 25, all one class |

60 000 generated inputs against the corrected oracle, zero divergences
(executed 2026-09-13). Three seeds rather than four: `opts` mutates three
grammars (the `<flags>\t<prebuffer>\t<prealloc>` framing, the document, and the
buffer length) but unlike `seq` its operations do not COMPOSE — each input is
one shot, so the reachable state space is the input space.

The fourth row is a control, and it is the point of running it. A corrected
reference oracle exists to stop a known divergence from drowning an unknown one
(LESSONS #28) — which means it can also hide a real bug if the correction is
wider than the decision it encodes. So the same mode was fuzzed against the
**PRISTINE** oracle and every finding classified mechanically: all 25 distinct
findings differ in `ppabuf` alone, on a call where `ppa=0`, with the port's
buffer all zeros. That is exactly the ledgered class and nothing else, so the
corrected oracle is masking the decision and not a defect. Asserting that a
correction is narrow is cheap; measuring it is what makes the other three rows
mean anything.

### High-budget sweep on the `parent` mode (LESSONS #33 + #42)

| Mode | Oracle | Seed | Iterations | Findings |
|---|---|---|---|---|
| `parent` | corrected | 1 | 20 000 | 0 |
| `parent` | corrected | 2 | 20 000 | 0 |
| `parent` | corrected | 3 | 20 000 | 0 |
| `parent` | **pristine** | 11 | 4 000 | 25, all one class |

60 000 generated inputs against the corrected oracle, zero divergences
(executed 2026-09-19). Three seeds: `parent` is single-shot, so unlike `seq` its
operations do not compose and the reachable state space is the input space.

The fourth row is the LESSONS #42 control, and this mode needs it more than most
— the correction added here patches *two* public entry points rather than one
expression, so "wider than the decision it encodes" is a live risk. The same
mode was fuzzed against the **PRISTINE** oracle and every finding classified
mechanically against the ledgered predicate — the C added (`rc=1`) and the port
refused (`rc=0`). All 25 distinct findings satisfy it; **0** fall outside. The
correction is exactly as wide as the class.

### High-budget sweep after lifting the `seq` array-only restriction (LESSONS #33 + #42)

| Mode | Seeds from | Oracle | Seed | Iterations | Findings |
|---|---|---|---|---|---|
| `seq` | `matrix-seq` | corrected | 1 / 2 / 3 | 20 000 each | 0 |
| `seq` | `matrix-place` | corrected | 1 / 2 / 3 | 20 000 each | 0 |
| `seq` | `matrix-place` | **pristine** | 21 | 4 000 | 16, all one class |

120 000 generated inputs against the corrected oracle, zero divergences
(executed 2026-09-19). Six runs rather than three because `seq` is the one mode
whose ops COMPOSE: an eight-op program reaches trees no single input describes,
so the reachable state space is larger than the input space.

**The sweep earned its budget twice over, and both findings were in work this
same change had just written:**

* At iteration 13 450 — six times past the gate's 2 000 floor — it found a real
  **port bug** that has nothing to do with the lift: `parse_index` capped the
  digit run at 18 characters *before* stripping leading zeros, so an index of
  `0000000000000000008` read as 0. The port detached element 0 where the C,
  whose `strtol` reads 8, detached nothing. Fixed, unit-pinned
  (`index_ignores_leading_zeros`), and added to `matrix-seq` and the seq probe
  set in the same change. It affected every mode that parses an index.
* At iteration 109, against the *corrected* oracle, it disproved a claim this
  change had written a few minutes earlier: that `cJSON_ReplaceItemInArray`
  needed no correction because a non-array has no children to find. True of a
  scalar; false of an object, whose members `get_array_item` walks happily —
  so `rep` index 0 on `{"x":1,"y":2}` yields `{"":0,"y":2}` and the key is
  gone. `make_fixed_core.py` gained a seventh correction.

The pristine row is the LESSONS #42 control: all 16 distinct findings satisfy
the ledgered predicate mechanically — some step where the C acted (`r=1`) and
the port refused (`r=0`) — with 0 outside it.

### What this table changed

Wiring it in moved the base library from "governed by prose" to a number that
cannot drift: 35 ungated entry points, declared, printed on every gate run, and
mechanically prevented from growing. The next module of this port is chosen from
the list above rather than from memory.
