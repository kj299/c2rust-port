/* Single-shot shims over the vendored cJSON, mirroring the Rust cdylib's
 * cjson_rt/cjson_rt_fmt so lib_diff can drive the whole parse→print pipeline in
 * one call and compare the C library against the Rust one. Compiled into
 * libcjson_c.so together with the pristine cJSON.c. */
#include <string.h>
#include "cJSON.h"

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
