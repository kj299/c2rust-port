# Port — cJSON (C → Rust)

The kit's first **real, foreign** port: cJSON v1.7.18, an MIT-licensed JSON parser
with a decade of CVE history. This is the keystone the retrospectives kept naming —
the moment the compounding loop stops feeding on itself and learns from code the
kit did not write (`RETROSPECTIVE-kit-audit.md` §6, keystone item).

## Status: **Phase 5 (cutover) — drop-in `.so` verified against the C at the ABI level**

> **Current numbers live in `progress.json` and `API-COVERAGE.md`, not here.**
> As of module 11: **13/13 tracked modules fully gated**, and **66 of 92
> exported symbols ported, 8 out-of-scope, 18 unported** against a declared
> ceiling the gate enforces. The narrative below is the port's history and its
> counts are as-of-then; the two files above are the ones a gate reads, so they
> are the ones to trust.

Phase 0 (inventory/plan) merged in #15; Phase 2 (oracle) merged in #16. The Rust
port now exists (`rust/`: `#![forbid(unsafe_code)]` core + differential driver)
with **six of seven modules** at the **fuzzed** gate — the entire CLI-observable
surface (parse, print, **minify**) is ported. The corpus is 86 C-validated
vectors; the differential covers all 79 (`matrix-ported.json` == the full
matrix now) — **79/79 MATCH**, including both CVE-class regressions live against
the Rust: `cve-lone-surrogate` (a167d9e OOB-read class) and **`cve-nesting-1001`**
(the stack-overflow guard — depth-1001 rejected, depth-1000 parses, the boundary
spiked and pinned). Differential FUZZING runs in **both** print and minify
modes, thousands of iterations, zero findings.

**The fuzzer earned its keep on minify.** A first minify-fuzz run found a real
divergence: the C's `minify_string` does not track escape parity, so a `\`
before a `"` escapes that quote even when the backslash is itself escaped
(`"\\" "` keeps its space). The escape-tracking port dropped the space;
the fix replicates the C's actual (arguably buggy) bytes, pinned in a unit test
and the `minify-escape-parity-quirk` corpus vector, and re-fuzzed 6000 iters
clean. This is the compounding loop working on foreign code: fuzz → find →
fix-forward → pin, in one change.

**Module 6 (`dom`) core is done** — constructors, accessors, `Add` builders,
`Compare`, and `Duplicate` (= clone) in pure safe Rust, differentially verified
through two new driver modes: **`dup`** (parse → `Duplicate` → print; must
byte-match a plain round-trip) and **`dup-eq`** (a value compares equal to its
duplicate). The `dup-eq` differential immediately earned its keep — its
C-baseline validation surfaced **two real `cJSON_Compare` quirks** the port must
reproduce: an `inf`/`nan` number never equals itself (`compare_double(inf,inf)` =
`nan <= inf` = false), and a value with **duplicate object keys** never compares
equal (the O(n²) first-match can't resolve the second key). Both pinned; dup and
dup-eq are 69/69 MATCH and fuzz-clean.

**The `cJSON_InitHooks` allocator decision landed: DROPPED and ledgered** — the
Rust port refuses to reproduce cJSON's process-global mutable allocator hooks (a
data-race hazard, CWE-362); it uses the global allocator with no `InitHooks`
equivalent (DIVERGENCES.md · `custom-allocator-dropped`).

**The C-ABI FFI `cdylib` is done and drop-in-verified.** `crates/ffi`
(`libcjson_rs.so`) is the port's ONLY `unsafe` — the audited `extern "C"` shim
over the `#![forbid(unsafe_code)]` core, **14 unsafe blocks, every one
`// SAFETY:`-documented** (the unsafe-audit gate's first real subject). It
exports the real `cJSON_*` parse/print/minify/compare/duplicate ABI over an
opaque handle, and `lib_diff` drives it against the pristine C `.so`
(`libcjson_c.so`, built from the vendored source) — **15/15 vectors MATCH at the
ABI level**, including `cJSON_Version`, `cJSON_Minify` in-place (the escape-parity
regression), and the full parse→print pipeline via single-shot shims. The Rust
library is a genuine drop-in replacement for the serialize/parse/minify surface.

**Documented remainder (not blocking):** the struct-field ABI (a caller reading
`item->valueint` directly rather than through accessors), the full `Add*`/`Get*`
builder surface over the FFI boundary, `create_reference`/`cJSON_IsReference`
aliasing, and the `sanitized` gate (miri/asan need a toolchain this environment
lacks — it rides the kit's CI-sanitizers backlog item). The safe-Rust
implementations of all of these already exist in `crates/core`; exposing the
rest over FFI is mechanical.

Next: the **kit retrospective** — LESSONS 017+ from the first foreign port
(the fuzz-found minify escape-parity bug, the two `cJSON_Compare` quirks, the
DBL_MAX lossy-print discovery, the `lib_diff --json` bytes bug this increment
found and fixed, and the "probe the oracle before you assume" discipline the
whole port ran on).

The `sanitized` gate stays honestly unset: miri/asan need toolchains this
environment lacks; they ride the CI-with-sanitizers item in the kit backlog.

String values are **bytes, not `String`** — probed against the oracle: cJSON
copies string content verbatim with no UTF-8 validation (a raw `0xFF`
round-trips), `\uZZZZ` (invalid hex) parses as a NUL rather than failing, and
the printer truncates at the first interior NUL. All three quirks are pinned in
unit tests and C-validated vectors.

Run the whole port gate (also a CI job, `cjson-port`):

    bash ports/cjson/check.sh   # oracle lock → fmt/clippy/test → diff_run 25/25 → unsafe-audit → progress ingest

First differential discovery, pinned in tests + vectors: **C's DBL_MAX printing
is lossy** — the `%1.15g` form reparses as *inf* (above DBL_MAX), and
`compare_double(inf, d)` = `inf ≤ inf·ε` is *true*, so C never falls back to 17
digits; `print(DBL_MAX)` → reparse → reprint gives `null`. The port reproduces
it byte-for-byte (see DIVERGENCES.md — faithfulness first, a "fix" would be a
ledgerable divergence).

| Artifact | What |
|---|---|
| `c/` | pristine, unmodified upstream source (the oracle's ground truth) + `PROVENANCE.md` (version, git hash, SHA-256s, license) |
| `FLAW-SCAN.md` | Phase-0 C-flaw inventory: the 17 copy-sink hits triaged + the historical CVE record the grep scanner *can't* see (the load-bearing half) |
| `PORT-PLAN.md` | module inventory, dependency graph, 7-module leaf-first port order, port shape, oracle strategy |
| `THREAT-MODEL.md` | trust boundaries, attacker capabilities, non-goals (passes `check_threat_model.py`) |
| `DIVERGENCES.md` | the intentional-divergence ledger — seeded with candidate divergences (trailing-garbage strictness, number formatting) and the structural-elimination list |
| `oracle/` | `driver.c` (CLI wrapper over the C lib), `build.sh`, `gen_corpus.py`, `matrix.json` (38) + `holdout.json` (7 hidden), `run.sh` (locks the oracle end-to-end) |
| `progress.json` | the 7-module tracker, all `not_started` |

### Lock/verify the oracle

    bash oracle/run.sh   # build driver → gen corpus → validate all 45 vectors vs C → CVE spot-check

The corpus's rejection cases are the load-bearing ones: `cve-nesting-1001`
(stack-overflow guard), `cve-lone-surrogate` (OOB-read class), and the
unterminated-block-comment minify (#338) are each confirmed to behave safely on
the C — these are where "safer than C" will be *tested*, not asserted, once the
Rust port runs against this same matrix.

## The one-paragraph finding

cJSON v1.7.18 is **hardened** C — unlike the adler32 toy (whose C had a live
overflow the port fixed), it already contains fixes for recursion-depth stack
overflow, OOB reads/writes, integer overflow, use-after-free, and NULL-deref. So
the port's job is **preserve-and-harden**: replicate the guards Rust does *not*
give for free (chiefly `CJSON_NESTING_LIMIT = 1000` — Rust recursion stack-
overflows too) and hold output byte-fidelity (the oracle's job), while letting
Rust *structurally* eliminate the classes it kills for free (UAF, dangling
realloc, OOB, NULL-deref). The flaw scanner found copy sinks; cJSON's real bug
class is arithmetic/lifetime/recursion — so the **fuzz + differential gates carry
the weight here**, exactly as `FLAW-SCAN.md` lays out.

## Next (on approval)

Copy `skeleton/` into `ports/cjson/rust/`, invoke `porting-kit-oracle` (build the
C driver + seed the corpus with the historical-CVE regression inputs), then port
module 1 (`alloc-node`) through all six gates.
