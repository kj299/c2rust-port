# Port — cJSON (C → Rust)

The kit's first **real, foreign** port: cJSON v1.7.18, an MIT-licensed JSON parser
with a decade of CVE history. This is the keystone the retrospectives kept naming —
the moment the compounding loop stops feeding on itself and learns from code the
kit did not write (`RETROSPECTIVE-kit-audit.md` §6, keystone item).

## Status: **Phase 4 in progress — modules 1–3 ported, 44/44 differential MATCH**

Phase 0 (inventory/plan) merged in #15; Phase 2 (oracle) merged in #16. The Rust
port now exists (`rust/`: `#![forbid(unsafe_code)]` core + differential driver)
with modules **alloc-node**, **scalar-parse**, and **string-parse** at the
`differential` gate — the kit's differential running green on foreign code. The
corpus is 69 vectors (all validated against C); the increment diffs the 44 whose
behavior the ported modules fully determine, including the `cve-lone-surrogate`
regression (the a167d9e OOB-read class) now exercised against the Rust.

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
