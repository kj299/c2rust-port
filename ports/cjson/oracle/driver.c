/* Differential driver over the vendored cJSON (the ORACLE side).
 *
 * cJSON is a library, not a program, so the executable differential (diff_run)
 * needs a thin CLI wrapper with a byte-for-byte deterministic contract that the
 * Rust port's driver will implement identically:
 *
 *   driver <mode>              # JSON bytes on stdin
 *     print                    parse, then cJSON_Print (formatted)
 *     print-unformatted        parse, then cJSON_PrintUnformatted
 *     roundtrip                alias for print-unformatted (the default диф case)
 *     minify                   cJSON_Minify in place
 *
 * Contract (both sides MUST match):
 *   - success: canonical result on stdout, exit 0.
 *   - parse failure: NOTHING on stdout, a stable "parse error at offset N" line
 *     on STDERR (diff_run ignores stderr by default), exit 1. The exact offset
 *     is C-implementation detail and is deliberately kept OFF stdout so it is not
 *     part of the compared contract (error *text* is a documented divergence).
 *   - allocation failure / usage: exit 2, nothing on stdout.
 *
 * Parsing uses cJSON_ParseWithLength so an embedded NUL or a missing terminator
 * can't run off the end — the historical parse_string OOB-read class (a167d9e)
 * is exactly what the corpus probes here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cjson_modes.h"

/* Read all of stdin into a malloc'd buffer. *out_len gets the byte count; the
 * buffer is NUL-terminated (one extra byte) so minify's C-string API is safe. */
static char *read_all_stdin(size_t *out_len) {
    size_t cap = 1 << 16, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 1 >= cap) {
            size_t ncap = cap * 2;
            char *nb = (char *)realloc(buf, ncap);
            if (!nb) { free(buf); return NULL; }
            buf = nb; cap = ncap;
        }
        size_t got = fread(buf + len, 1, cap - len - 1, stdin);
        len += got;
        if (got == 0) break;
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

/* The builder/query modes live in cjson_modes.c so the ABI shim
 * (../ffi/shim.c) runs the same code this driver does — one implementation per
 * side, as on the Rust side (see crates/core/src/modes.rs).
 *
 *   build     stdin is a VARIANT NAME, not JSON.
 *   query     stdin is "<key>\n<json>".
 */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: driver <print|print-unformatted|roundtrip|minify|build|query>\n");
        return 2;
    }
    const char *mode = argv[1];
    size_t len = 0;
    char *input = read_all_stdin(&len);
    if (!input) { fprintf(stderr, "oom reading stdin\n"); return 2; }

    if (strcmp(mode, "build") == 0) {
        /* stdin is a variant name; strip one trailing newline for convenience */
        if (len > 0 && input[len - 1] == '\n') input[--len] = '\0';
        char *out = cjson_modes_build(input);
        free(input);
        if (out == NULL) { fprintf(stderr, "unknown build variant\n"); return 2; }
        fputs(out, stdout);
        free(out);
        return 0;
    }

    if (strcmp(mode, "query") == 0) {
        char *nl = memchr(input, '\n', len);
        if (nl == NULL) {
            fprintf(stderr, "query needs <key>\\n<json>\n");
            free(input);
            return 2;
        }
        *nl = '\0';
        char *json = nl + 1;
        size_t json_len = len - (size_t)(json - input);
        char *out = cjson_modes_query(input, json, json_len);
        free(input);
        if (out == NULL) { fprintf(stderr, "parse error\n"); return 1; }
        fputs(out, stdout);
        free(out);
        return 0;
    }

    if (strcmp(mode, "minify") == 0) {
        /* Minify mutates a NUL-terminated C string in place; no validation. */
        cJSON_Minify(input);
        fputs(input, stdout);
        free(input);
        return 0;
    }

    cJSON *item = cJSON_ParseWithLength(input, len);
    if (item == NULL) {
        const char *err = cJSON_GetErrorPtr();
        fprintf(stderr, "parse error at offset %ld\n",
                err ? (long)(err - input) : -1L);
        free(input);
        return 1;
    }

    /* DOM invariant mode: a value compares equal to its duplicate. */
    if (strcmp(mode, "dup-eq") == 0) {
        cJSON *dup = cJSON_Duplicate(item, 1);
        int eq = (dup != NULL) && cJSON_Compare(item, dup, 1);
        fputs(eq ? "true" : "false", stdout);
        cJSON_Delete(dup);
        cJSON_Delete(item);
        free(input);
        return 0;
    }

    /* For `dup`, print the DUPLICATE (must byte-match a plain round-trip). */
    cJSON *to_print = item;
    cJSON *dup = NULL;
    if (strcmp(mode, "dup") == 0) {
        dup = cJSON_Duplicate(item, 1);
        if (dup == NULL) { fprintf(stderr, "duplicate failed\n"); cJSON_Delete(item); free(input); return 2; }
        to_print = dup;
    }

    char *out = NULL;
    if (strcmp(mode, "print") == 0) {
        out = cJSON_Print(to_print);
    } else { /* print-unformatted / roundtrip / dup */
        out = cJSON_PrintUnformatted(to_print);
    }
    int rc = 0;
    if (out == NULL) {
        fprintf(stderr, "print failed\n");
        rc = 2;
    } else {
        fputs(out, stdout);
        free(out);
    }
    cJSON_Delete(dup);
    cJSON_Delete(item);
    free(input);
    return rc;
}
