/* Shared cJSON_Utils driver modes — see cjson_utils_modes.c. Each returns a
 * malloc'd NUL-terminated string the caller frees with free(), or NULL on a
 * parse/allocation failure. `case_sensitive` selects the ...CaseSensitive C
 * entry point. */
#ifndef CJSON_UTILS_MODES_H
#define CJSON_UTILS_MODES_H

#include <stddef.h>

/* GetPointer: the value `pointer` resolves to, printed unformatted, or
 * "missing" when it resolves to nothing. */
char *cjson_utils_ptr(const char *pointer, const char *json, size_t json_len,
                      int case_sensitive);

/* ApplyPatches: "status=<N>;<doc-after>" — both the RFC-6902 status and the
 * mutated document are observable. */
char *cjson_utils_patch(const char *patches_json, size_t patches_len,
                        const char *doc_json, size_t doc_len,
                        int case_sensitive);

/* MergePatch (RFC 7396): the merged document, or "null". */
char *cjson_utils_merge(const char *patch_json, size_t patch_len,
                        const char *target_json, size_t target_len,
                        int case_sensitive);

/* GenerateMergePatch: the patch, or "null" when from == to. */
char *cjson_utils_genmerge(const char *from_json, size_t from_len,
                           const char *to_json, size_t to_len,
                           int case_sensitive);

/* GeneratePatches (RFC 6902): the patch array, or "null". */
char *cjson_utils_genpatch(const char *from_json, size_t from_len,
                           const char *to_json, size_t to_len,
                           int case_sensitive);

/* SortObject: the document with every object's members sorted by key. */
char *cjson_utils_sort(const char *json, size_t json_len, int case_sensitive);

#endif /* CJSON_UTILS_MODES_H */
