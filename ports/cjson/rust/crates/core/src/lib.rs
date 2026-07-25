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
//!   4. buffer-plumbing — ✅ the parse-side half (`ParseBuffer`, whitespace/BOM).
//!   5. recursive-core — ⏳ `[`/`{` currently fail the parse (NESTING_LIMIT is
//!      declared so the guard cannot be forgotten).
//!   6. dom / 7. entry-minify — ⏳.
//!
//! Every ⏳ arm returns a parse failure — the differential matrix for the
//! current increment (`oracle/matrix-ported.json`) only contains inputs whose
//! behavior is fully determined by the ported modules, so the diff verdict is
//! meaningful.
#![forbid(unsafe_code)]

pub mod num;
pub mod parse;
pub mod print;
pub mod string;
pub mod value;

pub use parse::{parse_with_length, ParseError};
pub use print::print_value;
pub use value::{Number, Value};
