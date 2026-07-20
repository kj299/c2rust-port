# Worked example — adler32 (the kit's v1.0 exit test)

A deliberately tiny **C-ABI library** driven through *every* gate of the kit
against its Rust port. This is the kit's own end-to-end shakedown — the "drive a
real library through the whole pipeline" exit test — kept as a runnable example.

```
./run.sh          # build + drive every gate (needs cc, cargo, python3)
```

## The point: the C is a spec that is itself buggy

`c/adler32.c` is the "obvious" Adler-32 — it accumulates `s1`/`s2` in `uint32_t`
and takes the modulo only at the end. Correct for short inputs, but `s2` grows
like *n²*, so on inputs longer than ~5800 bytes it **overflows** before the final
modulo and the checksum is wrong. `rust/` blocks every `NMAX = 5552` bytes (like
zlib) so no accumulator overflows, over a bounds-checked slice — **safer AND more
correct** than the C (the prime directive).

That difference is a *finding*, not a bug in the port: on a 10 000-byte input the
library differential reports a `DIVERGE`, and `DIVERGENCES.md` pins it as an
intentional fix-of-C-defect — so subsequent runs are clean while any *new*
divergence would still fail.

## What each gate shows

| Gate | Harness | Result on this port |
|---|---|---|
| flaw scan | `scan_c_flaws.py` | **0 findings** — the overflow is arithmetic, not a grep-able sink; this is *why* the differential exists |
| unsafe-audit | `audit_unsafe.py` | 1 `unsafe` block, documented → clean |
| library differential | `lib_diff.py` | 4 MATCH + 1 `DIVERGE(ledgered)` (the overflow) → clean |
| golden | `golden.py` | capture (C) + `--validate` + `--holdout`; iteration replay excludes the held-out vector, `--final` runs it → all MATCH |
| differential (exe path) | `diff_run.py` | C CLI vs Rust CLI → all MATCH |
| performance | `perf_gate.py` | Rust ≈ 0.9× the C median → PASS |
| differential fuzz | `diff_fuzz.py` | 0 findings on the small-input space (the large-input overflow is the vector suite's job — the two are complementary) |
| progress | `progress.py ingest` | driven `ported → differential → fuzzed → unsafe_audited` from the harness `--json` reports |

## Layout

```
c/       adler32.c/.h (the reference, with the latent bug) + adler_cli.c (stdin→hex)
rust/    the cdylib + rlib port and a matching CLI bin
vectors.json      lib_diff function-vector suite (incl. the overflow vector)
DIVERGENCES.md    the pinned fix-of-C-defect
pub/hold/matrix.json   golden + diff_run input matrices
run.sh    builds everything and drives all gates
```
