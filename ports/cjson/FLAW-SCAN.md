# Phase 0 — C-flaw inventory (cJSON v1.7.18 core)

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

## Net Phase-0 security posture

The port is **preserve-and-harden**, not fix-a-live-bug. The threat model
(`THREAT-MODEL.md`) and the port plan (`PORT-PLAN.md`) are built around the two
guards Rust does **not** give for free — **recursion depth** (must be replicated)
and **output byte-fidelity** (the oracle's job) — and the several classes it
**does** eliminate structurally (UAF, dangling-realloc, OOB read/write, NULL-deref).
