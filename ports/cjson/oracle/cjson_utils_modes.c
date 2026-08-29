/* Shared cJSON_Utils driver modes for the C side (JSON Pointer / Patch /
 * Merge-Patch / Sort). Same one-implementation-two-callers discipline as
 * cjson_modes.c (LESSONS #26): the executable driver and any ABI shim run this
 * exact code, so the differential and the ABI test cannot drift.
 *
 * Every entry point returns a malloc'd NUL-terminated string the caller frees
 * with free(), or NULL on failure (parse error / allocation failure). The
 * two-document modes take `a` and `b` already split on the framing newline —
 * valid compact JSON never contains a raw newline (in-string newlines are
 * escaped), so the driver's split-on-first-'\n' is unambiguous.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cJSON_Utils.h"
#include "cjson_utils_modes.h"

/* hand back plain malloc memory regardless of cJSON's configured allocator */
static char *dup_print(cJSON *item) {
    char *printed = cJSON_PrintUnformatted(item);
    if (printed == NULL) {
        return NULL;
    }
    char *out = strdup(printed);
    cJSON_free(printed);
    return out;
}

char *cjson_utils_ptr(const char *pointer, const char *json, size_t json_len,
                      int case_sensitive) {
    cJSON *doc = cJSON_ParseWithLength(json, json_len);
    if (doc == NULL) {
        return NULL;
    }
    cJSON *target = case_sensitive
        ? cJSONUtils_GetPointerCaseSensitive(doc, pointer)
        : cJSONUtils_GetPointer(doc, pointer);
    char *out = (target == NULL) ? strdup("missing") : dup_print(target);
    cJSON_Delete(doc);
    return out;
}

char *cjson_utils_patch(const char *patches_json, size_t patches_len,
                        const char *doc_json, size_t doc_len,
                        int case_sensitive) {
    cJSON *patches = cJSON_ParseWithLength(patches_json, patches_len);
    cJSON *doc = cJSON_ParseWithLength(doc_json, doc_len);
    if (patches == NULL || doc == NULL) {
        cJSON_Delete(patches);
        cJSON_Delete(doc);
        return NULL;
    }
    int status = case_sensitive
        ? cJSONUtils_ApplyPatchesCaseSensitive(doc, patches)
        : cJSONUtils_ApplyPatches(doc, patches);
    /* status then the resulting document — both are observable */
    char *printed = cJSON_PrintUnformatted(doc);
    char *out = NULL;
    if (printed != NULL) {
        size_t cap = strlen(printed) + 32;
        out = (char *)malloc(cap);
        if (out != NULL) {
            snprintf(out, cap, "status=%d;%s", status, printed);
        }
        cJSON_free(printed);
    }
    cJSON_Delete(patches);
    cJSON_Delete(doc);
    return out;
}

char *cjson_utils_merge(const char *patch_json, size_t patch_len,
                        const char *target_json, size_t target_len,
                        int case_sensitive) {
    cJSON *patch = cJSON_ParseWithLength(patch_json, patch_len);
    cJSON *target = cJSON_ParseWithLength(target_json, target_len);
    if (patch == NULL || target == NULL) {
        cJSON_Delete(patch);
        cJSON_Delete(target);
        return NULL;
    }
    /* MergePatch CONSUMES target and returns a new tree (possibly target). */
    cJSON *merged = case_sensitive
        ? cJSONUtils_MergePatchCaseSensitive(target, patch)
        : cJSONUtils_MergePatch(target, patch);
    char *out = (merged == NULL) ? strdup("null") : dup_print(merged);
    cJSON_Delete(merged);
    cJSON_Delete(patch);
    return out;
}

char *cjson_utils_genmerge(const char *from_json, size_t from_len,
                           const char *to_json, size_t to_len,
                           int case_sensitive) {
    cJSON *from = cJSON_ParseWithLength(from_json, from_len);
    cJSON *to = cJSON_ParseWithLength(to_json, to_len);
    if (from == NULL || to == NULL) {
        cJSON_Delete(from);
        cJSON_Delete(to);
        return NULL;
    }
    /* GenerateMergePatch sorts from/to in place and returns a new tree, or NULL
     * when the two are already equal. */
    cJSON *patch = case_sensitive
        ? cJSONUtils_GenerateMergePatchCaseSensitive(from, to)
        : cJSONUtils_GenerateMergePatch(from, to);
    char *out = (patch == NULL) ? strdup("null") : dup_print(patch);
    cJSON_Delete(patch);
    cJSON_Delete(from);
    cJSON_Delete(to);
    return out;
}

char *cjson_utils_genpatch(const char *from_json, size_t from_len,
                           const char *to_json, size_t to_len,
                           int case_sensitive) {
    cJSON *from = cJSON_ParseWithLength(from_json, from_len);
    cJSON *to = cJSON_ParseWithLength(to_json, to_len);
    if (from == NULL || to == NULL) {
        cJSON_Delete(from);
        cJSON_Delete(to);
        return NULL;
    }
    cJSON *patches = case_sensitive
        ? cJSONUtils_GeneratePatchesCaseSensitive(from, to)
        : cJSONUtils_GeneratePatches(from, to);
    char *out = (patches == NULL) ? strdup("null") : dup_print(patches);
    cJSON_Delete(patches);
    cJSON_Delete(from);
    cJSON_Delete(to);
    return out;
}

char *cjson_utils_sort(const char *json, size_t json_len, int case_sensitive) {
    cJSON *doc = cJSON_ParseWithLength(json, json_len);
    if (doc == NULL) {
        return NULL;
    }
    if (case_sensitive) {
        cJSONUtils_SortObjectCaseSensitive(doc);
    } else {
        cJSONUtils_SortObject(doc);
    }
    char *out = dup_print(doc);
    cJSON_Delete(doc);
    return out;
}
