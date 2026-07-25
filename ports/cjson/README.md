# Port — cJSON (C → Rust)

The kit's first **real, foreign** port: cJSON v1.7.18, an MIT-licensed JSON parser
with a decade of CVE history. This is the keystone the retrospectives kept naming —
the moment the compounding loop stops feeding on itself and learns from code the
kit did not write (`RETROSPECTIVE-kit-audit.md` §6, keystone item).

## Status: **Phase 2 complete (oracle locked) — no Rust written yet, awaiting review**

Phase 0 (inventory/flaw-scan/threat-model/plan) merged in #15. Phase 2 builds the
differential **oracle**: a C driver over the pristine source + a 45-vector corpus,
every vector validated against the C baseline.

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
