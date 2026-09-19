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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cjson_modes.h"
#include "cjson_utils_modes.h"

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
        fprintf(stderr, "usage: driver <print|...|build|query|access|construct|set|seq|opts|ptr|patch|merge|genmerge|genpatch|findptr|addpatch|sort (+ -cs)>\n");
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

    if (strcmp(mode, "access") == 0) {
        /* stdin is "<key>\t<index>\n<json>". Self-contained early return like
         * `query` above: it splits its OWN view and never falls through, so it
         * cannot corrupt the modes below it (LESSONS #27 — the bug there was a
         * branch mutating `input` that later branches still depended on). */
        char *nl = memchr(input, '\n', len);
        char *tab = nl ? memchr(input, '\t', (size_t)(nl - input)) : NULL;
        if (nl == NULL || tab == NULL) {
            fprintf(stderr, "access needs <key>\\t<index>\\n<json>\n");
            free(input);
            return 2;
        }
        *nl = '\0';
        *tab = '\0';
        char *json = nl + 1;
        size_t json_len = len - (size_t)(json - input);
        /* strtol, not atoi: the fuzzer WILL send a non-number and an overflowing
         * one, and atoi's answer there is undefined. Out-of-range clamps to
         * INT_MAX/INT_MIN, which is a value cJSON_GetArrayItem handles. */
        long idx = strtol(tab + 1, NULL, 10);
        if (idx > INT_MAX) idx = INT_MAX;
        if (idx < INT_MIN) idx = INT_MIN;
        char *out = cjson_modes_access(input, (int)idx, json, json_len);
        free(input);
        if (out == NULL) { fprintf(stderr, "parse error\n"); return 1; }
        fputs(out, stdout);
        free(out);
        return 0;
    }

    if (strcmp(mode, "construct") == 0) {
        /* stdin is "<count>\t<name>\t<raw>\n<payload>". Self-contained early
         * return like `access` above (LESSONS #27): it splits its OWN view of
         * `input` and never falls through, so it cannot corrupt the modes
         * below it. */
        char *nl = memchr(input, '\n', len);
        char *t1 = nl ? memchr(input, '\t', (size_t)(nl - input)) : NULL;
        char *t2 = t1 ? memchr(t1 + 1, '\t', (size_t)(nl - t1 - 1)) : NULL;
        if (nl == NULL || t1 == NULL || t2 == NULL) {
            fprintf(stderr, "construct needs <count>\\t<name>\\t<raw>\\n<payload>\n");
            free(input);
            return 2;
        }
        *nl = '\0';
        *t1 = '\0';
        *t2 = '\0';
        /* strtol, not atoi, for the same reason as `access`: the fuzzer sends
         * junk and overflowing digits, and atoi's answer there is undefined.
         * Kept as a long and clamped inside cjson_modes_construct, which is
         * where the C's own `count < 0` guard is exercised. */
        long count = strtol(input, NULL, 10);
        if (count > INT_MAX) count = INT_MAX;
        if (count < INT_MIN) count = INT_MIN;
        const unsigned char *payload = (const unsigned char *)(nl + 1);
        size_t payload_len = len - (size_t)((char *)payload - input);
        char *out = cjson_modes_construct(count, t1 + 1, t2 + 1, payload, payload_len);
        free(input);
        if (out == NULL) { fprintf(stderr, "construct failed\n"); return 1; }
        fputs(out, stdout);
        free(out);
        return 0;
    }

    if (strcmp(mode, "set") == 0) {
        /* stdin is "<bits>\t<key>\t<newstr>\n<json>". Self-contained early
         * return like `construct` above (LESSONS #27): it splits its OWN view
         * of `input` and never falls through. */
        char *nl = memchr(input, '\n', len);
        char *t1 = nl ? memchr(input, '\t', (size_t)(nl - input)) : NULL;
        char *t2 = t1 ? memchr(t1 + 1, '\t', (size_t)(nl - t1 - 1)) : NULL;
        if (nl == NULL || t1 == NULL || t2 == NULL) {
            fprintf(stderr, "set needs <bits>\\t<key>\\t<newstr>\\n<json>\n");
            free(input);
            return 2;
        }
        *nl = '\0';
        *t1 = '\0';
        *t2 = '\0';
        /* The double arrives as its raw IEEE-754 bits in hex, not as decimal
         * text. Decimal would put libc's strtod on the compared contract (the
         * same trap `access` avoids when it PRINTS doubles as bits), and it
         * could not spell the values this mode exists for: a NaN payload, a
         * signalling NaN, -0.0. Hand-rolled rather than strtoull so the two
         * sides share one two-line rule instead of two libraries' notions of
         * "leading 0x, whitespace, and overflow". */
        unsigned long long bits = 0;
        const char *h = input;
        for (int n = 0; *h != '\0' && n < 16; h++, n++) {
            int d;
            if (*h >= '0' && *h <= '9') d = *h - '0';
            else if (*h >= 'a' && *h <= 'f') d = *h - 'a' + 10;
            else if (*h >= 'A' && *h <= 'F') d = *h - 'A' + 10;
            else break;
            bits = (bits << 4) | (unsigned long long)d;
        }
        double num;
        memcpy(&num, &bits, sizeof num);
        const char *json = nl + 1;
        size_t json_len = len - (size_t)(json - input);
        char *out = cjson_modes_set(num, t1 + 1, t2 + 1, json, json_len);
        free(input);
        if (out == NULL) { fprintf(stderr, "set failed\n"); return 1; }
        fputs(out, stdout);
        free(out);
        return 0;
    }

    if (strcmp(mode, "opts") == 0) {
        /* stdin is "<flags>\t<prebuffer>\t<prealloc>\n<json>". Self-contained
         * early return like `set` above (LESSONS #27): it splits its OWN view
         * of `input` and never falls through.
         *
         * `json` is `nl + 1` into a buffer read_all_stdin already
         * NUL-terminated, which is what lets cJSON_ParseWithOpts (a
         * `const char *` API) be called on the same bytes the length form
         * gets -- their differing views of those bytes is the point. */
        char *nl = memchr(input, '\n', len);
        char *t1 = nl ? memchr(input, '\t', (size_t)(nl - input)) : NULL;
        char *t2 = t1 ? memchr(t1 + 1, '\t', (size_t)(nl - t1 - 1)) : NULL;
        if (nl == NULL || t1 == NULL || t2 == NULL) {
            fprintf(stderr, "opts needs <flags>\\t<prebuffer>\\t<prealloc>\\n<json>\n");
            free(input);
            return 2;
        }
        *nl = '\0';
        *t1 = '\0';
        *t2 = '\0';
        /* strtol + clamp, for the same reason as `access` and `construct`: the
         * fuzzer sends junk and overflowing digits, and atoi's answer there is
         * undefined. Negatives survive the clamp deliberately -- they are the
         * guards cJSON_PrintBuffered and cJSON_PrintPreallocated actually have. */
        long flags = strtol(input, NULL, 10);
        long prebuffer = strtol(t1 + 1, NULL, 10);
        long prealloc = strtol(t2 + 1, NULL, 10);
        if (flags > INT_MAX) flags = INT_MAX;
        if (flags < INT_MIN) flags = INT_MIN;
        if (prebuffer > INT_MAX) prebuffer = INT_MAX;
        if (prebuffer < INT_MIN) prebuffer = INT_MIN;
        if (prealloc > INT_MAX) prealloc = INT_MAX;
        if (prealloc < INT_MIN) prealloc = INT_MIN;
        const char *json = nl + 1;
        size_t json_len = len - (size_t)(json - input);
        char *out = cjson_modes_opts((int)flags, (int)prebuffer, (int)prealloc,
                                     json, json_len);
        free(input);
        if (out == NULL) { fprintf(stderr, "opts failed\n"); return 1; }
        fputs(out, stdout);
        free(out);
        return 0;
    }

    if (strcmp(mode, "seq") == 0) {
        /* stdin is "<json>\n<op>\t<sel>\t<arg>\n...". Self-contained early
         * return like `set` above (LESSONS #27). Valid compact JSON never
         * carries a raw newline, so the first one ends the document
         * unambiguously; everything after it is the op program. */
        char *nl = memchr(input, '\n', len);
        const char *json = input;
        size_t json_len = nl ? (size_t)(nl - input) : len;
        const char *ops = nl ? nl + 1 : "";
        size_t ops_len = nl ? len - (size_t)(ops - input) : 0;
        char *out = cjson_modes_seq(json, json_len, ops, ops_len);
        free(input);
        if (out == NULL) { fprintf(stderr, "seq: parse error\n"); return 1; }
        fputs(out, stdout);
        free(out);
        return 0;
    }

    /* cJSON_Utils modes. The two-document modes split stdin on the first '\n':
     * valid compact JSON never carries a raw newline, so the split is
     * unambiguous.
     *
     * CRUCIAL (LESSONS #27): decide `is_utils` BEFORE touching `input`, and only
     * split when it is actually a utils mode. An earlier version NUL-terminated
     * at the first newline unconditionally, which silently corrupted the
     * fall-through modes (minify/print/roundtrip/dup) for any newline-bearing
     * input — the shared driver's new branch mutating state the OTHER branches
     * depend on. The pre-existing modes' differential fuzz is what caught it. */
    {
        int cs = 0;
        const char *base = mode;
        size_t mlen = strlen(mode);
        if (mlen > 3 && strcmp(mode + mlen - 3, "-cs") == 0) {
            cs = 1;
            /* compare only the prefix before "-cs" below via base+len checks */
        }
        int is_utils =
            strcmp(base, "ptr") == 0      || strcmp(base, "ptr-cs") == 0      ||
            strcmp(base, "patch") == 0    || strcmp(base, "patch-cs") == 0    ||
            strcmp(base, "merge") == 0    || strcmp(base, "merge-cs") == 0    ||
            strcmp(base, "genmerge") == 0 || strcmp(base, "genmerge-cs") == 0 ||
            strcmp(base, "genpatch") == 0 || strcmp(base, "genpatch-cs") == 0 ||
            strcmp(base, "findptr") == 0  || strcmp(base, "findptr-cs") == 0  ||
            strcmp(base, "addpatch") == 0 ||
            strcmp(base, "sort") == 0     || strcmp(base, "sort-cs") == 0;
        if (is_utils) {
            char *nl = memchr(input, '\n', len);
            char *b = nl ? nl + 1 : NULL;
            size_t alen = nl ? (size_t)(nl - input) : len;
            size_t blen = nl ? len - (size_t)(b - input) : 0;
            if (nl) *nl = '\0';   /* NUL-terminate the first field for the C APIs */

            char *out = NULL;
            if (strcmp(base, "ptr") == 0 || strcmp(base, "ptr-cs") == 0) {
                out = nl ? cjson_utils_ptr(input, b, blen, cs) : NULL;
            } else if (strcmp(base, "patch") == 0 || strcmp(base, "patch-cs") == 0) {
                out = nl ? cjson_utils_patch(input, alen, b, blen, cs) : NULL;
            } else if (strcmp(base, "merge") == 0 || strcmp(base, "merge-cs") == 0) {
                out = nl ? cjson_utils_merge(input, alen, b, blen, cs) : NULL;
            } else if (strcmp(base, "genmerge") == 0 || strcmp(base, "genmerge-cs") == 0) {
                out = nl ? cjson_utils_genmerge(input, alen, b, blen, cs) : NULL;
            } else if (strcmp(base, "genpatch") == 0 || strcmp(base, "genpatch-cs") == 0) {
                out = nl ? cjson_utils_genpatch(input, alen, b, blen, cs) : NULL;
            } else if (strcmp(base, "findptr") == 0 || strcmp(base, "findptr-cs") == 0) {
                /* a = pointer to the target, b = json */
                out = nl ? cjson_utils_findptr(input, b, blen, cs) : NULL;
            } else if (strcmp(base, "addpatch") == 0) {
                /* a = "<op>\t<path>", b = optional value JSON */
                char *tab = strchr(input, '\t');
                if (nl && tab != NULL) {
                    *tab = '\0';
                    out = cjson_utils_addpatch(input, tab + 1, b, blen);
                } else {
                    out = NULL;
                }
            } else { /* sort / sort-cs: one document, whole buffer */
                if (nl) *nl = '\n';   /* undo split — sort takes the whole buffer */
                if (len > 0 && input[len - 1] == '\n') input[--len] = '\0';
                out = cjson_utils_sort(input, len, cs);
            }
            free(input);
            if (out == NULL) { fprintf(stderr, "utils: parse error\n"); return 1; }
            fputs(out, stdout);
            free(out);
            return 0;
        }
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
