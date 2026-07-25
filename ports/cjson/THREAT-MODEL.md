# Threat model — cJSON (C→Rust port, v1.7.18 core)

cJSON is a JSON parser/serializer: its entire purpose is to consume **untrusted
bytes** and build/emit a document. It is almost pure attack surface. "Secure" here
means: no input can cause memory unsafety, a crash (panic/abort/stack overflow),
unbounded resource use, or a silent behavioral divergence from the hardened C.

## 1. Assets — what are we protecting?

- The integrity of the **host process** that links this library — a JSON parser is
  usually deep inside a larger service, so a parser memory-safety bug is a
  remote-code-execution primitive for whatever embeds it.
- The **availability** of that process: a single malicious document must not crash
  it (stack overflow via deep nesting, panic via a bad `unwrap`, OOM via a size
  lie) or hang it.
- **Behavioral fidelity** with the C: downstream code depends on exact parse
  results and exact printed bytes; a silent divergence is a correctness/security
  bug in the consumer (e.g. a signature computed over re-serialized JSON).

## 2. Trust boundaries — where does untrusted data cross in?

Every public entry point takes attacker-controlled bytes. These are the fuzz +
validation priorities.

| Entry point | Source | Trust | Ported module |
|---|---|---|---|
| `cJSON_Parse` / `cJSON_ParseWithLength` / `…Opts` | any caller's byte buffer | **untrusted** | `port_core::parse` (modules 2–5, 7) |
| `cJSON_Minify` (mutates a caller `char*` in place) | untrusted byte buffer | **untrusted** | `port_core::minify` (module 7) |
| `cJSON_SetValuestring`, `Add*`, `Create*String/Raw` | caller-supplied C strings | **untrusted** (may be non-UTF-8, may alias) | `port_core::dom` (module 6) |
| `cJSON_InitHooks` custom allocator | caller (operator-ish) | **semi-trusted**, but global mutable state | `port_core::alloc` (module 1) |
| numeric locale (`localeconv`) | process environment | trusted-ish | `parse_number`/`print_number` (module 2) |

## 3. Privilege transitions

**None.** cJSON makes no syscalls, spawns nothing, needs no privilege, and drops
none. There is no OS-integration seam and no FFI to a privileged service. The only
"transition" is the C-ABI boundary itself: the `extern "C"` functions receive raw
pointers and lengths from C callers, so the port's `unsafe` surface is confined to
that FFI shim (pointer validation at the boundary), audited by `audit_unsafe.py`,
with a `#![forbid(unsafe_code)]` safe core beneath it.

## 4. Attacker capabilities we defend against

- **Arbitrary / truncated / non-UTF-8 bytes** on any parse entry point (→ no
  panic/UB, no out-of-bounds read: the fuzz gate, and the historical `parse_string`
  OOB-read regression a167d9e as a pinned corpus input).
- **Pathologically deep nesting** — `[[[[…` to any depth (→ **must reject at
  `CJSON_NESTING_LIMIT = 1000`, not stack-overflow**; this is the one C guard Rust
  does not inherit for free, and the highest-priority spike/fuzz target).
- **Pathological sizes** — a huge document, or a length argument that lies about a
  buffer (→ no integer overflow in buffer growth, no OOM from a trusted size: the
  `ensure`/`#189`/`#230` fixes preserved as checked arithmetic).
- **Malicious string content** — unterminated strings, bad `\u` escapes, lone
  UTF-16 surrogates, embedded NULs, unterminated block comments to `cJSON_Minify`
  (→ the `#338` minify OOB read+write regression, pinned).
- **Aliasing / lifetime abuse** — a `valuestring` passed to `AddItemToObject` that
  aliases the object's own field (→ the `#248` use-after-free class, eliminated
  structurally by Rust ownership rather than detected).

## 5. Explicit non-goals

- We do **not** defend against a malicious caller who has already compromised the
  host process (e.g. one that passes a garbage `cJSON*` the library never handed
  out — the C ABI cannot validate provenance of an opaque pointer; documented as a
  precondition, same as the C).
- **No constant-time / side-channel guarantees** — JSON parsing is not a secret-
  dependent operation here; timing is out of scope.
- **Custom-allocator parity is provisional:** cJSON's global mutable `global_hooks`
  is itself a thread-safety hazard; if the port cannot offer per-call allocator
  injection safely, dropping `cJSON_InitHooks` (with a logged divergence) is
  preferred over reproducing shared mutable statics. Stated so reviewers don't
  assume drop-in allocator compatibility.

## 6. C-defect inventory (from the Phase-0 scan)

See `FLAW-SCAN.md`. The grep scanner returned 17 copy-sink hits (none a live bug
in v1.7.18); the *load-bearing* inventory is the historical CVE/security record
from `CHANGELOG.md` — recursion depth, OOB read/write, integer overflow, UAF,
NULL-deref — each of which the port must **preserve** (depth limit, output size)
or **eliminate structurally** (UAF, dangling realloc, OOB, NULL-deref). Every
confirmed fix that changes observable output becomes a `DIVERGENCES.md` entry;
every historical-CVE input becomes a pinned oracle corpus seed.
