//! Modules 4/5 (the parse-side buffer plumbing + value dispatch), ported from
//! cJSON.c:288–305 (`parse_buffer`), 1047–1096 (whitespace/BOM), 1104–1195
//! (`cJSON_ParseWithLengthOpts`), 1325–1378 (`parse_value`).
//!
//! Two C quirks are ported FAITHFULLY on purpose (a silent "improvement" here
//! would be an unledgered divergence):
//!   * `buffer_skip_whitespace` (cJSON.c:1047): after skipping to the very end
//!     of the buffer it backs the offset up by one.
//!   * `skip_utf8_bom` (cJSON.c:1072): requires FIVE readable bytes
//!     (`can_access_at_index(buffer, 4)`) to strip a 3-byte BOM, so a 4-byte
//!     document like BOM+"1" keeps its BOM and fails to parse — same as C.

use crate::num::parse_number;
use crate::string::parse_string;
use crate::value::Value;

/// cJSON.h:137 `CJSON_NESTING_LIMIT` — THE guard Rust does not provide for
/// free (Rust recursion overflows the stack like C's). Declared with the
/// buffer so the recursive-core module cannot land without seeing it.
pub const NESTING_LIMIT: usize = 1000;

/// cJSON.c:288 `parse_buffer` (the hooks field is ownership now).
pub struct ParseBuffer<'a> {
    pub content: &'a [u8],
    pub offset: usize,
    pub depth: usize,
}

/// Parse failure with the position the C error path would report
/// (cJSON.c:1160–1170: `offset` clamped to the last valid index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub position: usize,
}

impl<'a> ParseBuffer<'a> {
    fn can_access(&self, index: usize) -> bool {
        // C can_access_at_index: offset + index < length (bounded: offset and
        // index are both <= content.len() <= isize::MAX)
        self.offset.saturating_add(index) < self.content.len()
    }
    fn can_read(&self, size: usize) -> bool {
        // C can_read: offset + size <= length
        self.offset.saturating_add(size) <= self.content.len()
    }
    fn rest(&self) -> &'a [u8] {
        &self.content[self.offset.min(self.content.len())..]
    }
}

/// cJSON.c:1047 `buffer_skip_whitespace` — anything <= 0x20 is whitespace,
/// including NUL; the end-of-buffer back-up quirk is kept.
fn skip_whitespace(buf: &mut ParseBuffer) {
    if !buf.can_access(0) {
        return;
    }
    while buf.can_access(0) && buf.content[buf.offset] <= 32 {
        buf.offset = buf.offset.saturating_add(1);
    }
    if buf.offset == buf.content.len() {
        buf.offset = buf.offset.saturating_sub(1); // faithful C quirk
    }
}

/// cJSON.c:1072 `skip_utf8_bom` — only at offset 0, and only when 5 bytes are
/// readable (the faithful off-by-the-spec quirk described in the header).
fn skip_utf8_bom(buf: &mut ParseBuffer) {
    if buf.offset != 0 {
        return;
    }
    if buf.can_access(4) && buf.content.starts_with(b"\xEF\xBB\xBF") {
        buf.offset = 3;
    }
}

/// cJSON.c:1325 `parse_value` — literal dispatch in the C's exact order.
/// The ⏳ arms (string / array / object) are NOT yet ported and fail the parse;
/// the increment's differential matrix contains no input that reaches them
/// with a C-accepting document (see lib.rs porting status).
fn parse_value(buf: &mut ParseBuffer) -> Result<Value, ()> {
    if buf.can_read(4) && buf.rest().starts_with(b"null") {
        buf.offset = buf.offset.saturating_add(4);
        return Ok(Value::Null);
    }
    if buf.can_read(5) && buf.rest().starts_with(b"false") {
        buf.offset = buf.offset.saturating_add(5);
        return Ok(Value::False);
    }
    if buf.can_read(4) && buf.rest().starts_with(b"true") {
        buf.offset = buf.offset.saturating_add(4);
        return Ok(Value::True);
    }
    if buf.can_access(0) && buf.content[buf.offset] == b'"' {
        // module 3: parse_string sets the offset (past-quote or error site)
        return parse_string(buf).map(Value::String);
    }
    if buf.can_access(0)
        && (buf.content[buf.offset] == b'-' || buf.content[buf.offset].is_ascii_digit())
    {
        // module 2: parse_number consumes exactly what strtod accepted
        return match parse_number(buf.rest()) {
            Some((n, consumed)) => {
                buf.offset = buf.offset.saturating_add(consumed);
                Ok(Value::Number(n))
            }
            None => Err(()),
        };
    }
    if buf.can_access(0) && buf.content[buf.offset] == b'[' {
        return Err(()); // ⏳ module 5 (recursive-core) not yet ported
    }
    if buf.can_access(0) && buf.content[buf.offset] == b'{' {
        return Err(()); // ⏳ module 5 (recursive-core) not yet ported
    }
    Err(())
}

/// cJSON.c:1104 `cJSON_ParseWithLengthOpts` (as used by the driver contract:
/// the buffer is the exact byte length read, no NUL appended). On success
/// returns the value and the offset one past the last consumed byte — trailing
/// bytes are the caller's laxness decision, exactly like C's
/// `require_null_terminated=false` default.
pub fn parse_with_length(bytes: &[u8]) -> Result<(Value, usize), ParseError> {
    if bytes.is_empty() {
        return Err(ParseError { position: 0 }); // C: 0 == buffer_length → fail
    }
    let mut buf = ParseBuffer {
        content: bytes,
        offset: 0,
        depth: 0,
    };
    skip_utf8_bom(&mut buf);
    skip_whitespace(&mut buf);
    match parse_value(&mut buf) {
        Ok(v) => Ok((v, buf.offset)),
        Err(()) => {
            // cJSON.c:1160: position = offset if still in-bounds, else the
            // last valid index.
            let position = if buf.offset < bytes.len() {
                buf.offset
            } else {
                bytes.len().saturating_sub(1)
            };
            Err(ParseError { position })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    fn parse(s: &[u8]) -> Result<(Value, usize), ParseError> {
        parse_with_length(s)
    }

    #[test]
    fn scalars_parse() {
        assert_eq!(parse(b"true").unwrap().0, Value::True);
        assert_eq!(parse(b"false").unwrap().0, Value::False);
        assert_eq!(parse(b"null").unwrap().0, Value::Null);
        assert!(matches!(parse(b"42").unwrap().0, Value::Number(_)));
        assert!(matches!(parse(b"  -17  ").unwrap().0, Value::Number(_)));
    }

    #[test]
    fn rejects_like_c() {
        assert!(parse(b"").is_err()); // empty → fail (C: 0 == buffer_length)
        assert!(parse(b"xyzzy").is_err());
        assert!(parse(b"-").is_err()); // strtod consumes nothing
        assert!(parse(b"   ").is_err()); // whitespace only
        assert!(parse(b"tru").is_err()); // truncated literal
    }

    #[test]
    fn trailing_bytes_are_lax_like_c() {
        // "123 456" → the value 123, offset 3; trailing bytes ignored by the
        // require_null_terminated=false contract (pinned as trailing-garbage
        // laxness in DIVERGENCES.md candidates).
        let (v, consumed) = parse(b"123 456").unwrap();
        assert!(matches!(v, Value::Number(n) if n.d == 123.0));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn bom_quirk_is_faithful() {
        // 5+ readable bytes: BOM stripped, number parses
        assert!(parse(b"\xEF\xBB\xBF42").is_ok());
        // exactly 4 bytes: C's can_access_at_index(buffer, 4) is false, the
        // BOM stays, parse fails — faithful quirk, do not "fix" silently
        assert!(parse(b"\xEF\xBB\xBF1").is_err());
    }
}
