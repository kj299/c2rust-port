/* Shared builder/query modes for the C side — see cjson_modes.c for why this is
 * a library rather than two copies. Both return malloc'd NUL-terminated strings
 * the caller frees with free(), or NULL on failure (unknown variant, parse
 * error, allocation failure). */
#ifndef CJSON_MODES_H
#define CJSON_MODES_H

#include <stddef.h>

/* Build the named document with the cJSON builder API; returns it printed
 * unformatted. NULL for an unknown variant. */
char *cjson_modes_build(const char *variant);

/* Look `key` up in `json` and describe it via the Is* predicates and the struct
 * fields (type/valueint/valuestring). Returns "missing" when the key is absent,
 * NULL when the document does not parse. */
char *cjson_modes_query(const char *key, const char *json, size_t json_len);

#endif /* CJSON_MODES_H */
