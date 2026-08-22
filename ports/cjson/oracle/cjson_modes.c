/* The C side's builder/query modes, as a library.
 *
 * Both the differential driver (`driver.c`, an executable diff_run runs) and the
 * ABI shim (`../ffi/shim.c`, compiled into libcjson_c.so for lib_diff) need this
 * exact behavior. Implementing it twice would let the two drift and each still
 * look green — the same trap the Rust side had between `crates/driver` and the
 * probe glue, fixed the same way: one implementation, two thin callers.
 *
 * Both entry points return a malloc'd NUL-terminated string the caller frees,
 * or NULL on failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cjson_modes.h"

/* Fixed-order predicate flags: one letter per cJSON_Is* that answers true. */
static void append_flags(char *buf, size_t cap, const cJSON *it) {
    char f[16];
    size_t n = 0;
    if (cJSON_IsInvalid(it)) f[n++] = 'I';
    if (cJSON_IsNull(it))    f[n++] = 'N';
    if (cJSON_IsFalse(it))   f[n++] = 'F';
    if (cJSON_IsTrue(it))    f[n++] = 'T';
    if (cJSON_IsBool(it))    f[n++] = 'B';
    if (cJSON_IsNumber(it))  f[n++] = 'M';
    if (cJSON_IsString(it))  f[n++] = 'S';
    if (cJSON_IsRaw(it))     f[n++] = 'R';
    if (cJSON_IsArray(it))   f[n++] = 'A';
    if (cJSON_IsObject(it))  f[n++] = 'O';
    f[n] = '\0';
    strncat(buf, f, cap - strlen(buf) - 1);
}

char *cjson_modes_build(const char *variant) {
    cJSON *root = NULL;
    if (strcmp(variant, "flat") == 0) {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "s", "hi");
        cJSON_AddNumberToObject(root, "n", 42);
        cJSON_AddBoolToObject(root, "t", 1);
        cJSON_AddBoolToObject(root, "f", 0);
        cJSON_AddNullToObject(root, "z");
    } else if (strcmp(variant, "array") == 0) {
        root = cJSON_CreateArray();
        cJSON_AddItemToArray(root, cJSON_CreateNumber(1));
        cJSON_AddItemToArray(root, cJSON_CreateString("two"));
        cJSON_AddItemToArray(root, cJSON_CreateTrue());
        cJSON_AddItemToArray(root, cJSON_CreateNull());
    } else if (strcmp(variant, "nested") == 0) {
        root = cJSON_CreateObject();
        cJSON *arr = cJSON_CreateArray();
        cJSON *inner = cJSON_CreateObject();
        cJSON_AddNumberToObject(inner, "deep", -1);
        cJSON_AddItemToArray(arr, inner);
        cJSON_AddItemToObject(root, "arr", arr);
    } else if (strcmp(variant, "numbers") == 0) {
        root = cJSON_CreateArray();
        cJSON_AddItemToArray(root, cJSON_CreateNumber(0));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(-1));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(0.1));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(1e308));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(1.0 / 0.0));  /* inf */
    } else if (strcmp(variant, "dupkey") == 0) {
        /* probed: the same key twice APPENDS, it does not replace */
        root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "k", 1);
        cJSON_AddNumberToObject(root, "k", 2);
    } else if (strcmp(variant, "add-null") == 0) {
        /* probed: adding a NULL item is silently ignored */
        root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "a", NULL);
        cJSON_AddNumberToObject(root, "b", 1);
    } else if (strcmp(variant, "empty") == 0) {
        root = cJSON_CreateObject();
    } else if (strcmp(variant, "strings") == 0) {
        root = cJSON_CreateArray();
        cJSON_AddItemToArray(root, cJSON_CreateString(""));
        cJSON_AddItemToArray(root, cJSON_CreateString("a\"b\\c"));
        cJSON_AddItemToArray(root, cJSON_CreateString("tab\there"));
    } else {
        return NULL;
    }
    if (root == NULL) return NULL;
    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (printed == NULL) return NULL;
    /* hand back plain malloc memory so the caller frees with free() regardless
     * of which allocator cJSON was built with */
    char *out = strdup(printed);
    cJSON_free(printed);
    return out;
}

char *cjson_modes_query(const char *key, const char *json, size_t json_len) {
    cJSON *item = cJSON_ParseWithLength(json, json_len);
    if (item == NULL) return NULL;
    cJSON *got = cJSON_GetObjectItemCaseSensitive(item, key);
    if (got == NULL) {
        cJSON_Delete(item);
        return strdup("missing");
    }
    char *printed = cJSON_PrintUnformatted(got);
    if (printed == NULL) { cJSON_Delete(item); return NULL; }

    size_t cap = strlen(printed) + 256
               + (got->valuestring ? strlen(got->valuestring) : 1);
    char *out = (char *)malloc(cap);
    if (out == NULL) { cJSON_free(printed); cJSON_Delete(item); return NULL; }
    out[0] = '\0';
    strncat(out, "is=", cap - 1);
    append_flags(out, cap, got);
    /* the struct fields a C caller reads straight off the pointer */
    size_t n = strlen(out);
    snprintf(out + n, cap - n, ";type=%d;int=%d;str=%s;size=%d;print=%s",
             got->type, got->valueint,
             got->valuestring ? got->valuestring : "-",
             cJSON_GetArraySize(got), printed);
    cJSON_free(printed);
    cJSON_Delete(item);
    return out;
}
