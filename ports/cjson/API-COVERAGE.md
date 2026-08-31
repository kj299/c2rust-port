# API coverage — every exported symbol must be accounted for

`harnesses/api-coverage/check_api.py` reads the table below and the C header, and
**fails the gate if an exported symbol has no row** (or a row has drifted from a
symbol the header no longer exports). `out-of-scope` is allowed, but only with a
written reason — an unexplained exclusion is exactly what this gate exists to
prevent.

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

## Not yet covered by this gate — stated plainly

`c/cJSON.h` (the base library, ~80 exported symbols) is **not** yet wired into
`check_api.py`. The gate runs today over `cJSON_Utils.h` only, so the base
library's public surface is still governed by prose rather than by a check. That
is a real, known hole and the honest next step — writing its manifest is a
sizeable job, and claiming coverage it does not have would repeat the failure
this whole gate was built to fix.
