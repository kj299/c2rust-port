# examples/adler32 — the kit's v1.0 exit test

A real, tiny C→Rust **library** port driven through every gate of the kit, end to
end. This is the epic's definition of done: proof the kit works on a real port, and
a runnable reference for your own.

```
./run.sh          # needs cc + cargo (NOT part of `make check-kit`, which is toolchain-free)
```

## The point: a C spec that is itself buggy

`c/adler32.c` is the "obvious" Adler-32 — it accumulates `s1`/`s2` in `uint32_t`
and takes the modulo only at the end, so `s2` **overflows** on inputs longer than
~5800 bytes. `rust/` blocks every `NMAX = 5552` bytes (like zlib) over a
bounds-checked slice: **safer and more correct**. That difference is not a port
bug — it's the prime directive in action (don't re-implement a C defect), and it is
recorded as an intentional fix-of-C-defect in the divergence ledger.

## What `run.sh` drives

| Gate | What it shows |
|---|---|
| `scan_c_flaws` | **0 findings** — the overflow is arithmetic, not a grep-able sink |
| `unsafe-audit` | the one FFI `unsafe` block carries a `// SAFETY:` → clean |
| `cando` | main's driver-based library differential: the overflow → `DIVERGE(ledgered)` |
| `lib_diff` | the complementary ctypes differential: same overflow, caught the same way |
| `golden` | capture with `--validate` + `--holdout`; iteration excludes the held-out vector, `--final` runs it |
| `diff_run` | the executable path (C CLI vs Rust CLI) |
| `perf_gate` | 5 MB workload, Rust well under the 1.3× budget (`--floor-ms` keeps it honest) |
| `diff-fuzz` | small-input space, 0 findings |
| `progress` | ingests the `--json` reports to auto-advance `ported → … → unsafe_audited` |

## The lesson it teaches

The gates **divide labor**. `scan_c_flaws` and `diff-fuzz` both found *nothing*; the
**library differential** found the bug. "0 findings" from one gate is not "safe" —
that is what the others are for. Fixed vectors own the large-input edge; fuzzing
owns the shape-space near its seeds; they are complementary, not redundant.

Everything except the sources and `run.sh` is generated/built and gitignored.
