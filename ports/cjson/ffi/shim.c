/* Single-shot shims over the vendored cJSON, mirroring the Rust cdylib's
 * cjson_rt/cjson_rt_fmt so lib_diff can drive the whole parse→print pipeline in
 * one call and compare the C library against the Rust one. Compiled into
 * libcjson_c.so together with the pristine cJSON.c. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cJSON.h"
#include "../oracle/cjson_modes.h"

static int rt(const char *json, char *out, int out_size, int fmt) {
    if (json == NULL) return -1;
    cJSON *item = cJSON_ParseWithLength(json, strlen(json));
    if (item == NULL) return -1;
    char *printed = fmt ? cJSON_Print(item) : cJSON_PrintUnformatted(item);
    if (printed == NULL) { cJSON_Delete(item); return -1; }
    int len = (int)strlen(printed);
    if (out_size > 0 && out != NULL) {
        int copy = len < (out_size - 1) ? len : (out_size - 1);
        memcpy(out, printed, (size_t)copy);
        out[copy] = '\0';
    }
    cJSON_free(printed);
    cJSON_Delete(item);
    return len;
}

int cjson_rt(const char *json, char *out, int out_size)     { return rt(json, out, out_size, 0); }
int cjson_rt_fmt(const char *json, char *out, int out_size) { return rt(json, out, out_size, 1); }

/* ---- builder/query surface, single-shot for lib_diff ----------------------
 * Same contract as cjson_rt: write up to out_size-1 bytes plus NUL into `out`
 * and return the FULL length (so truncation is observable), or -1 on failure.
 * The behavior itself comes from ../oracle/cjson_modes.c — the same translation
 * unit the differential driver runs, so the ABI test and the executable test
 * cannot drift apart. */
static int emit(char *dst, int cap, const char *src) {
    int len = (int)strlen(src);
    if (cap > 0 && dst != NULL) {
        int copy = len < (cap - 1) ? len : (cap - 1);
        memcpy(dst, src, (size_t)copy);
        dst[copy] = '\0';
    }
    return len;
}

int cjson_build_variant(const char *variant, char *out, int out_size) {
    if (variant == NULL) return -1;
    char *s = cjson_modes_build(variant);
    if (s == NULL) return -1;
    int len = emit(out, out_size, s);
    free(s);
    return len;
}

int cjson_query_desc(const char *key, const char *json, char *out, int out_size) {
    if (key == NULL || json == NULL) return -1;
    char *s = cjson_modes_query(key, json, strlen(json));
    if (s == NULL) return -1;
    int len = emit(out, out_size, s);
    free(s);
    return len;
}

/* ---- cJSON_Parse + cJSON_GetErrorPtr, as a two-call SEQUENCE --------------
 * The error is state: it outlives the call that set it, and lib_diff runs every
 * vector in a fresh process, so the sequence has to live inside one shim to be
 * compared at all. Each step is cJSON_Parse(s), or with `use_length`
 * cJSON_ParseWithLength(s, strlen(s)) -- the other entry point that sets the
 * error, and the one that resets it even for a NULL input (length 0).
 * Writes "first=<step>;second=<step>", each step being
 * "ok:<printed>@<where>" or "fail@<where>", where <where> is `null`, `a<n>` /
 * `b<n>` (byte n of the first / second input, terminator included), or
 * `other`. Positions are computed from ADDRESSES and never dereferenced: a
 * stale pointer is exactly the case that must not be read. Same spelling as
 * the Rust cdylib's cjson_parse_seq. */
static void locate_error(char *dst, size_t cap, const char *err,
                         const char *a, const char *b) {
    const char *bases[2] = { a, b };
    const char tags[2] = { 'a', 'b' };
    if (err == NULL) { snprintf(dst, cap, "null"); return; }
    for (int i = 0; i < 2; i++) {
        if (bases[i] == NULL) continue;
        /* uintptr_t: relational operators on pointers into DIFFERENT objects
         * are undefined in C, and "is it inside this buffer?" is that test. */
        uintptr_t e = (uintptr_t)err, base = (uintptr_t)bases[i];
        if (e >= base && e - base <= strlen(bases[i])) {
            snprintf(dst, cap, "%c%lu", tags[i], (unsigned long)(e - base));
            return;
        }
    }
    snprintf(dst, cap, "other");
}

static char *parse_step(const char *input, int use_length,
                        const char *a, const char *b) {
    cJSON *item = use_length
        ? cJSON_ParseWithLength(input, input ? strlen(input) : 0)
        : cJSON_Parse(input);
    const char *err = cJSON_GetErrorPtr();
    char where[32];
    locate_error(where, sizeof where, err, a, b);
    char *printed = item ? cJSON_PrintUnformatted(item) : NULL;
    size_t cap = (printed ? strlen(printed) : 0) + sizeof where + 8;
    char *out = (char *)malloc(cap);
    if (out != NULL) {
        if (item == NULL) snprintf(out, cap, "fail@%s", where);
        else snprintf(out, cap, "ok:%s@%s", printed ? printed : "", where);
    }
    cJSON_free(printed);
    cJSON_Delete(item);
    return out;
}

int cjson_parse_seq(const char *first, const char *second, int second_is_null,
                    int use_length, char *out, int out_size) {
    if (second_is_null) second = NULL;
    char *s1 = parse_step(first, use_length, first, second);
    char *s2 = parse_step(second, use_length, first, second);
    int len = -1;
    if (s1 != NULL && s2 != NULL) {
        size_t cap = strlen(s1) + strlen(s2) + 16;
        char *desc = (char *)malloc(cap);
        if (desc != NULL) {
            snprintf(desc, cap, "first=%s;second=%s", s1, s2);
            len = emit(out, out_size, desc);
            free(desc);
        }
    }
    free(s1);
    free(s2);
    return len;
}
