/* Single-shot shims over the vendored cJSON, mirroring the Rust cdylib's
 * cjson_rt/cjson_rt_fmt so lib_diff can drive the whole parse→print pipeline in
 * one call and compare the C library against the Rust one. Compiled into
 * libcjson_c.so together with the pristine cJSON.c. */
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
