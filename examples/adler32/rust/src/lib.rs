//! A memory-safe, arithmetically-correct Adler-32 — the Rust port of the C
//! reference in `../c/adler32.c`. The C accumulates in `uint32_t` and takes the
//! modulo only at the end, so its `s2` overflows on long inputs. This port blocks
//! every `NMAX` bytes (like zlib) so no accumulator ever overflows, and computes
//! over a bounds-checked slice — safer AND more correct than the C.
//!
//! The pure function lives here; the C-ABI export and the CLI both call it.

const MOD_ADLER: u32 = 65521;
/// Largest block length for which s1/s2 cannot overflow u32 between modulos.
const NMAX: usize = 5552;

/// Adler-32 over a byte slice. Pure, panic-free, no `unsafe`.
pub fn adler32_bytes(data: &[u8]) -> u32 {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for chunk in data.chunks(NMAX) {
        for &b in chunk {
            s1 += u32::from(b);
            s2 += s1;
        }
        s1 %= MOD_ADLER;
        s2 %= MOD_ADLER;
    }
    (s2 << 16) | s1
}

/// C-ABI entry point (same symbol as the C `adler32`, so `lib_diff` diffs them
/// interchangeably).
///
/// # Safety
/// `data` must be valid for reads of `len` bytes, or `len` must be 0 (then
/// `data` may be null). This mirrors the C contract exactly.
#[no_mangle]
pub unsafe extern "C" fn adler32(data: *const u8, len: usize) -> u32 {
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: by the documented contract `data` is valid for `len` reads, and
        // `len > 0` here so the pointer is dereferenceable; the slice borrows for
        // the duration of this call only.
        unsafe { core::slice::from_raw_parts(data, len) }
    };
    adler32_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::adler32_bytes;

    #[test]
    fn known_vectors() {
        assert_eq!(adler32_bytes(b""), 0x0000_0001);
        assert_eq!(adler32_bytes(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32_bytes(b"abc"), 0x024D_0127);
    }
}
