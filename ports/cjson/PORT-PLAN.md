# Phase 0/1 — module inventory & dependency-ordered port plan (cJSON v1.7.18)

Scope of this port: **`cJSON.c` (3143 LOC) + `cJSON.h` (300 LOC)** — parse, print,
and the DOM. `cJSON_Utils.{c,h}` (JSON-Pointer/Patch/Merge) is a later increment.

## Port shape

**Translate-with-FFI-coexistence**, not reimplement-behind-a-seam. cJSON is a
pure computational library (no syscalls, no OS integration — includes are only
`string.h/stdio.h/math.h/stdlib.h/limits.h/ctype.h/float.h/locale.h`), and it
ships a stable C ABI that downstream code links against. The Rust port keeps that
exact `extern "C"` surface (83 `CJSON_PUBLIC` symbols) so the differential can run
the C and Rust builds interchangeably (`lib_diff` / `cando`), and so a real
consumer could drop in the Rust `.so`. See `C-to-Rust-Playbook-Best-of-Both.md`
(the executable/library split; Step 0 C→C preconditioning is not needed — the code
is already clean ANSI C).

## No OS/FFI failure-mode surface (LESSONS #1 classification)

The "classify the FFI/syscall surface by failure mode" step comes back **empty**,
and that is a finding, not an omission: cJSON makes **no** blocking calls, needs
**no** privilege, and has **no** OS/version-variant behavior. The one
platform-variant is `get_decimal_point()` (reads `localeconv()` — the locale's
decimal separator, cJSON.c:279); it is pure and cheap to spike. So **no module
needs a pre-port hazard spike** — the winlsof failure mode simply doesn't apply
here. The hazards are all *internal* (recursion depth, arithmetic, lifetimes),
which is why the fuzz + differential gates carry the weight (see `FLAW-SCAN.md`).

## Internal dependency graph (leaf-first)

```
                      cJSON_New_Item, internal_hooks (alloc)      ← leaf: allocation + node
                      case_insensitive_strcmp, cJSON_strdup       ← leaf: primitives
                                    │
        ┌───────────────────────────┼───────────────────────────┐
   parse_number            parse_string (parse_hex4,        get_decimal_point
   (get_decimal_point)      utf16_literal_to_utf8)          print_number
                                    │
                            buffer_skip_whitespace, skip_utf8_bom, ensure, update_offset   ← buffer plumbing
                                    │
                            parse_value ⇄ print_value        ← the recursive core
                             │   │   │
                    parse_array parse_object  (mutually recursive, depth-guarded)
                    print_array print_object
                                    │
                    ┌───────────────┴───────────────┐
              DOM builders/accessors           cJSON_Parse / cJSON_Print / cJSON_Minify   ← public entry points
              (Create*, Add*, Get*, Detach*,    cJSON_Duplicate, cJSON_Compare
               Delete, Insert, Replace)
```

## Dependency-ordered module plan (each testable against the oracle the moment it lands)

| # | Module | Key functions | Why here / hazard | Gate emphasis |
|---|---|---|---|---|
| 1 | **alloc + node** | `internal_hooks`, `cJSON_New_Item`, `cJSON_Delete`, `cJSON_strdup` | Leaf. Owns the allocator seam. Rust: `Box`/`Vec` — the `#189` dangling-realloc class dies here. **Global mutable `global_hooks`/`global_error` (cJSON.c:92,186) is the one thread-safety hazard** — the port must not reproduce shared mutable statics (make hooks a parse-time parameter or drop custom-allocator support with a logged divergence). | unsafe-audit (FFI), differential |
| 2 | **scalar parse/print** | `parse_number`, `print_number`, `get_decimal_point`, `parse_hex4` | Leaf compute. Number formatting (`%1.15g`/`%1.17g`, cJSON.c:580,586) is the byte-fidelity risk — **the differential's job**; any divergence is ledgered. Locale decimal-point is the only platform-variant. | **differential** (number formatting), fuzz |
| 3 | **string parse/print** | `parse_string`, `print_string_ptr`, `utf16_literal_to_utf8`, `parse_hex4` | Historical OOB-read site (a167d9e). UTF-16 surrogate handling is fiddly. Rust: slices + `char` — OOB read class dies; surrogate logic must match. | **fuzz** (truncated/invalid UTF-8, surrogates), differential |
| 4 | **buffer plumbing** | `ensure`, `update_offset`, `buffer_skip_whitespace`, `skip_utf8_bom`, `parse_buffer` | The `ensure` integer-overflow-before-realloc fix (2683d4d) lives here. Rust: `Vec` growth — overflow class structural, but **preserve the intent** so output size matches. | fuzz, differential |
| 5 | **recursive core** | `parse_value`/`print_value`, `parse_array`/`parse_object`, `print_array`/`print_object` | **THE hazard module. `CJSON_NESTING_LIMIT = 1000` (cJSON.h:137, enforced cJSON.c:1459 & 1619) MUST be replicated** — Rust recursion stack-overflows too; this is the one C guard Rust does not give for free. Spike a `[[[…]]]`-to-depth-1001 input first. | **fuzz** (deep nesting → must reject at 1000, not crash), differential |
| 6 | **DOM build/query** | `cJSON_Create*`, `Add*`, `Get*`, `Detach*`, `Insert*`, `Replace*`, `Duplicate`, `Compare` | Roots. The `#248` UAF (string aliasing in `AddItemToObject`) and CVE-2023-50471 (`InsertItemInArray` NULL) live here — Rust ownership/`Option` kill both classes. `create_reference`/`IsReference` aliasing needs a careful ownership model. | unsafe-audit, differential, **cando** (per-function vectors) |
| 7 | **entry points + minify** | `cJSON_Parse[WithLength][Opts]`, `cJSON_Print[Buffered/Preallocated]`, `cJSON_Minify` | Public seam. `cJSON_Minify` is the `#338` OOB read+write site — Rust rewrite as a bounded state machine. | **differential** (full round-trips), **diff-fuzz**, cando |

## Why this order

Leaf-first so every module can be diffed against the C oracle the instant it lands
(PLAYBOOK Phase 1 exit criterion). Modules 1–4 are independently testable via
`cando`/`lib_diff` per-function vectors; module 5 is the first that needs the full
recursive round-trip (and the nesting-limit spike **before** it is scheduled —
the one place the winlsof "spike the scary module first" rule fires); modules 6–7
are the public entry points the executable-level differential (`diff_run` over a
CLI wrapper) and `diff-fuzz` exercise end to end.

## Oracle strategy (Phase 2 preview — not built yet)

- **Corpus seeds:** upstream `tests/` inputs (the Unity suite + `tests/inputs/`
  real-world JSON) + `json-patch-tests`, drawn on at oracle-build time (not
  vendored under `c/`, which is source-under-port only).
- **Regression pins:** one input per historical CVE in `FLAW-SCAN.md` — especially
  a depth-1001 nesting input (must *reject*, not crash), a truncated `\uD800`
  surrogate (OOB-read regression), and a minify input with an unterminated block
  comment (`#338`). These are the inputs where "safer than C" is *tested*, not
  asserted.
- **Differential drivers:** a thin C driver (`driver.template.c`) over the vendored
  `cJSON.c` = oracle; the Rust `cdylib` = port; `lib_diff`/`cando` diff them.

## Deliverables of this Phase 0 (done)

`ports/cjson/c/` (pristine source + `PROVENANCE.md`), `FLAW-SCAN.md`,
`THREAT-MODEL.md` (passes the threat-model gate), this plan, and the seeded
`progress.json`. **No Rust written.** Next, on approval: copy `skeleton/`, invoke
`porting-kit-oracle`, and start module 1.
