//! `cjson_core` — the safe core of the cJSON port (v1.7.18 as the C reference).
//!
//! `#![forbid(unsafe_code)]`: nothing in this crate can reach for `unsafe`, so
//! every historical cJSON memory-safety class (OOB read/write, UAF, dangling
//! realloc) is unrepresentable here by construction. The C-ABI surface, when it
//! arrives with the `dom` module, lives in a separate audited crate.
//!
//! Porting status (ports/cjson/PORT-PLAN.md, module order):
//!   1. alloc-node — ✅ `value`: the owned tree; C's malloc/free discipline
//!      becomes ownership (`Box`/`String`/`Vec`).
//!   2. scalar-parse — ✅ `num` + the scalar arms of `parse`/`print`.
//!   3. string-parse — ✅ `string`: parse/print with the C's probed quirks
//!      (invalid-hex→NUL, print-truncates-at-NUL, verbatim non-UTF-8 bytes).
//!   4. buffer-plumbing — ✅ parse side (`ParseBuffer`, whitespace/BOM); the
//!      print side (`ensure`/`update_offset`) is subsumed by `Vec` growth,
//!      whose bounds/overflow behavior is what the C's guards hand-built.
//!   5. recursive-core — ✅ `parse_array`/`parse_object` + the printer, with
//!      the NESTING_LIMIT depth guard (the one guard Rust doesn't inherit;
//!      spiked: depth-1000 parses, depth-1001 rejects).
//!   7. entry-minify — ✅ `minify`: cJSON_Minify with the #338 bound made
//!      structural (slice indices, no raw pointer walk).
//!   6. dom — ✅ (core) `dom`: constructors, accessors, Add builders,
//!      Compare, Duplicate (= clone). Custom-allocator parity DROPPED (a
//!      thread-safety hazard, ledgered).
//!  15. entry-opts — ✅ the four *WithOpts*/buffered entry points:
//!      `parse_with_length_opts` (`require_null_terminated` and the parse-end
//!      offset), `parse_with_opts` (the C's `strlen + 1` buffer),
//!      `print_buffered` and `print_preallocated` — the last of which put the
//!      C's `ensure` accounting back on the compared contract (see `print`).
//!
//! The C-ABI FFI cdylib (`crates/ffi`, `libcjson_rs.so`) wraps this core and is
//! ABI-differentially verified drop-in against the pristine C `.so` (lib_diff,
//! 15/15). It is the ONLY crate with `unsafe`; this core stays forbid-unsafe.
//!
//! The differential matrix (`oracle/matrix-ported.json`) now covers the ENTIRE
//! CLI surface — parse, print, and minify. Only the DOM builder/query API and
//! the C-ABI FFI crate (module 6) remain.
#![forbid(unsafe_code)]

pub mod dom;
pub mod minify;
pub mod modes;
pub mod num;
pub mod parse;
pub mod print;
pub mod string;
pub mod utils;
pub mod value;

pub use minify::minify;
pub use parse::{parse_with_length, parse_with_length_opts, parse_with_opts, ParseError};
pub use print::{print_buffered, print_preallocated, print_value};
pub use value::{Number, Value};
