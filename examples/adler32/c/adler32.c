/* adler32.c — the "obvious" implementation, and a textbook latent bug.
 *
 * It accumulates s1 and s2 in uint32_t and takes the modulo only ONCE, at the
 * end. Correct for short inputs; but s2 grows like ~n^2, so on inputs longer
 * than ~5800 high-valued bytes s2 overflows uint32_t BEFORE the final modulo and
 * the checksum is wrong. Real zlib blocks every NMAX = 5552 bytes to prevent
 * exactly this. This is the kind of defect a port must FIX, not faithfully
 * reproduce (the prime directive: the C is a spec that may itself be buggy).
 *
 * There is no memory-unsafety here for scan_c_flaws to grep — the bug is
 * arithmetic, which is precisely why the differential + fuzzing gates exist. */
#include "adler32.h"

#define MOD_ADLER 65521u

uint32_t adler32(const uint8_t *data, size_t len) {
    uint32_t s1 = 1, s2 = 0;
    for (size_t i = 0; i < len; i++) {
        s1 += data[i];   /* no periodic modulo — s2 can overflow before line below */
        s2 += s1;
    }
    return ((s2 % MOD_ADLER) << 16) | (s1 % MOD_ADLER);
}
