/* cando-style function-level differential driver — C ORACLE side.
 * Protocol: `driver <func> [args...]` → print the result CANONICALLY to stdout,
 * exit 0 on success, nonzero on error/unsupported. The Rust driver
 * (rust/src/bin/adler_drv.rs) prints byte-identically. Keep it THIN. */
#include <stdio.h>
#include <string.h>
#include "adler32.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <func> [args...]\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "adler32") == 0) {
        if (argc < 3) return 3;   /* bad vector: adler32 needs a data arg */
        const char *s = argv[2];
        printf("%08x\n", adler32((const uint8_t *)s, strlen(s)));
        return 0;
    }
    fprintf(stderr, "unsupported function: %s\n", argv[1]);
    return 4;
}
