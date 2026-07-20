/* Thin CLI over the C library so the executable-shaped gates (diff_run,
 * perf-gate, diff-fuzz, golden) can drive it: read all of stdin, print the
 * Adler-32 as 8 lowercase hex digits. */
#include <stdio.h>
#include <stdlib.h>
#include "adler32.h"

int main(void) {
    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return 2;
    int c;
    while ((c = getchar()) != EOF) {
        if (len == cap) {
            cap *= 2;
            uint8_t *grown = realloc(buf, cap);
            if (!grown) { free(buf); return 2; }
            buf = grown;
        }
        buf[len++] = (uint8_t)c;
    }
    printf("%08x\n", adler32(buf, len));
    free(buf);
    return 0;
}
