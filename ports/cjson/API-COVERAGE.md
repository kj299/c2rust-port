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

**92 exported symbols across both headers: 54 ported, 8 out-of-scope, 30
unported.** This port covers cJSON_Utils completely and the base library's
parse / print / minify / query / build / **accessor** surface; **it does not
cover the base library's mutation API** (detach, delete, insert, replace, and
most of the typed-array and setter constructors). Anything that reads "cJSON is
ported" without that sentence is overclaiming, which is why the gate prints the
shortfall on every run rather than only on failure.

api-coverage: max-unported = 30

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
| `cJSONUtils_GetPointerCaseSensitive` | ported | same, `cs=true` — driver mode `ptr-cs` |
| `cJSONUtils_ApplyPatches` | ported | `utils::apply_patches` — driver mode `patch` |
| `cJSONUtils_ApplyPatchesCaseSensitive` | ported | same, `cs=true` — driver mode `patch-cs` |
| `cJSONUtils_MergePatch` | ported | `utils::merge_patch` — driver mode `merge` |
| `cJSONUtils_MergePatchCaseSensitive` | ported | same, `cs=true` — driver mode `merge-cs` |
| `cJSONUtils_GenerateMergePatch` | ported | `utils::generate_merge_patch` — driver mode `genmerge` |
| `cJSONUtils_GenerateMergePatchCaseSensitive` | ported | same, `cs=true` — driver mode `genmerge-cs` |
| `cJSONUtils_GeneratePatches` | ported | `utils::create_patches` — driver mode `genpatch` |
| `cJSONUtils_GeneratePatchesCaseSensitive` | ported | same, `cs=true` — driver mode `genpatch-cs` |
| `cJSONUtils_SortObject` | ported | `utils::sort_object` — driver mode `sort` |
| `cJSONUtils_SortObjectCaseSensitive` | ported | same, `cs=true` — driver mode `sort-cs` |
| `cJSONUtils_FindPointerFromObjectTo` | ported | `utils::find_pointer_from_object_to` — driver mode `findptr` |
| `cJSONUtils_AddPatchToArray` | ported | `utils::add_patch_to_array` — driver mode `addpatch` |

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
  an ABI vector calls it. Several `unported` rows are exercised *transitively*
  (cJSON_Utils calls them internally, so the utils modes do compare their effect);
  that is noted where true, but it is not the same thing, and calling it "ported"
  is precisely the rounding-up this gate exists to stop. Their own contract —
  NULL arguments, type mismatches, detached-item ownership — is never called.

### Ported — 40

| Symbol | Status | Where it is gated |
|---|---|---|
| `cJSON_Version` | ported | ABI vector `version` (`ffi/vectors.json`) |
| `cJSON_Parse` | ported | cdylib export; driver modes `parse` / `roundtrip` |
| `cJSON_ParseWithLength` | ported | cdylib export; shim `cjson_rt`, all ABI `rt-*` vectors |
| `cJSON_Print` | ported | cdylib export; shim `cjson_rt_fmt`, ABI `rt-fmt-*` vectors |
| `cJSON_PrintUnformatted` | ported | cdylib export; shim `cjson_rt`, driver mode `print` |
| `cJSON_Delete` | ported | cdylib export; every mode's teardown, checked under miri/ASan |
| `cJSON_Minify` | ported | cdylib export; driver mode `minify`, 4 ABI vectors |
| `cJSON_Duplicate` | ported | cdylib export; driver mode `dup` |
| `cJSON_Compare` | ported | cdylib export; driver mode `compare` |
| `cJSON_free` | ported | cdylib export; frees every string the print modes return |
| `cJSON_GetErrorPtr` | ported | driver mode `parse` reports the error offset |
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
| `cJSON_AddItemToArray` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddItemToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddNullToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddBoolToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddNumberToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_AddStringToObject` | ported | `cjson_modes_build` — driver mode `build` |
| `cJSON_GetArrayItem` | ported | `dom::get_array_item` — driver mode `access` (`iarr=`) |
| `cJSON_GetObjectItem` | ported | `dom::get_object_item(.., case_sensitive=false)` — driver mode `access` (`kobj=`) |
| `cJSON_HasObjectItem` | ported | `dom::has_object_item` — driver mode `access` (`has=`) |
| `cJSON_GetStringValue` | ported | `dom::get_string_value` — driver mode `access` (`kstr=`/`istr=`) |
| `cJSON_GetNumberValue` | ported | `dom::get_number_value` — driver mode `access` (`knum=`/`inum=`) |

### Out of scope — 8, each a deliberate refusal under the Prime Directive

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

### Unported — 30, against the ceiling declared at the top

Real work not done, recorded as such. Grouped by what would be needed.

| Symbol | Status | What is missing |
|---|---|---|
| `cJSON_ParseWithOpts` | unported | the `return_parse_end` / `require_null_terminated` options surface; no driver mode passes options |
| `cJSON_ParseWithLengthOpts` | unported | same options surface, length-delimited |
| `cJSON_PrintBuffered` | unported | the prebuffer growth strategy; only the default printer is compared |
| `cJSON_PrintPreallocated` | unported | caller-owned output buffer. Needs a mode that compares the truncation/failure boundary, which is the interesting part — the header warns the estimate is not exact ("allocate 5 bytes more than you actually need") |
| `cJSON_CreateFalse` | unported | `cjson_modes_build` builds `true` but never `false` |
| `cJSON_CreateBool` | unported | the bool-dispatching constructor |
| `cJSON_CreateRaw` | unported | raw passthrough nodes — worth a mode of their own, since raw content bypasses the printer's escaping |
| `cJSON_CreateIntArray` | unported | bulk typed-array constructor (`count`-driven loop, a classic overflow sink) |
| `cJSON_CreateFloatArray` | unported | same |
| `cJSON_CreateDoubleArray` | unported | same |
| `cJSON_CreateStringArray` | unported | same |
| `cJSON_AddTrueToObject` | unported | convenience constructor, no build variant exercises it |
| `cJSON_AddFalseToObject` | unported | same |
| `cJSON_AddRawToObject` | unported | same, and inherits the raw-passthrough question above |
| `cJSON_AddObjectToObject` | unported | same |
| `cJSON_AddArrayToObject` | unported | same |
| `cJSON_DetachItemViaPointer` | unported | the whole detach/delete/insert/replace mutation API is absent from the compared surface. It is the part of cJSON that rewires the sibling/child list in place — i.e. the part where a use-after-free would actually live — so it needs its own module and its own mutation-sequence fuzzer, not a bolted-on mode |
| `cJSON_DetachItemFromArray` | unported | as above |
| `cJSON_DeleteItemFromArray` | unported | as above |
| `cJSON_DetachItemFromObject` | unported | as above; reached transitively via cJSON_Utils' patch `move`/`remove` ops |
| `cJSON_DetachItemFromObjectCaseSensitive` | unported | as above; reached transitively via the `-cs` utils modes |
| `cJSON_DeleteItemFromObject` | unported | as above; reached transitively via merge-patch's null-deletes (the "removes only the FIRST duplicate" fix came from that path) |
| `cJSON_DeleteItemFromObjectCaseSensitive` | unported | as above; reached transitively via the `-cs` utils modes |
| `cJSON_InsertItemInArray` | unported | as above |
| `cJSON_ReplaceItemViaPointer` | unported | as above |
| `cJSON_ReplaceItemInArray` | unported | as above |
| `cJSON_ReplaceItemInObject` | unported | as above |
| `cJSON_ReplaceItemInObjectCaseSensitive` | unported | as above |
| `cJSON_SetNumberHelper` | unported | in-place number mutation behind the `cJSON_SetNumberValue` macro; needs the mutation surface above |
| `cJSON_SetValuestring` | unported | in-place string replacement. cJSON reuses the existing buffer when the new string is no longer than the old — a length-dependent branch that is exactly what a differential mode should be pinning |

### What this table changed

Wiring it in moved the base library from "governed by prose" to a number that
cannot drift: 35 ungated entry points, declared, printed on every gate run, and
mechanically prevented from growing. The next module of this port is chosen from
the list above rather than from memory.
