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

/* The ACCESSOR surface, all five entry points in one shot (LESSONS #26: an
 * accessor no mode calls is ungated whatever the matrix says):
 * cJSON_GetObjectItem (CASE-INSENSITIVE — the case-sensitive one is already on
 * `query`), cJSON_HasObjectItem, cJSON_GetArrayItem, cJSON_GetStringValue and
 * cJSON_GetNumberValue. The last two are deliberately fed the lookup RESULTS,
 * which may be NULL, because tolerating NULL is part of their contract.
 * Returns NULL when the document does not parse. */
char *cjson_modes_access(const char *key, int index,
                         const char *json, size_t json_len);

/* The CONSTRUCTOR surface, all twelve entry points in one shot (LESSONS #26):
 * cJSON_CreateFalse, cJSON_CreateBool, cJSON_CreateRaw, the four typed-array
 * constructors (Int/Float/Double/String), and the five Add*ToObject helpers
 * (True/False/Raw/Object/Array).
 *
 * `payload` supplies the array elements as whole little-endian groups from
 * DISJOINT thirds -- ints, then doubles, then floats -- while the string array
 * reads the whole payload split on NUL. The regions are disjoint so that no two
 * arrays reinterpret the same bytes at different widths: an f64 infinity's high
 * four bytes are an f32 NaN, and an INT_MIN/INT_MAX pair is an f64 NaN, so
 * sharing made every interesting value unprobeable (see cjson_modes.c). `count`
 * is the caller's requested element count, passed through the C's own
 * `count < 0` guard; a NULL element pointer is reached by an empty region.
 *
 * `count` is clamped to the elements the payload actually holds, and that is a
 * deliberate limit of this gate, not an oversight. The four typed-array
 * constructors take a (pointer, count) pair with NO way to check that the
 * pointer really has `count` elements, so a count past the buffer is an
 * out-of-bounds read — undefined behavior in the ORACLE, which has no defined
 * answer to compare against. The port removes the hazard structurally (its core
 * takes a slice, so the pair cannot disagree), and that improvement is
 * therefore invisible to a differential test by construction. Recorded in
 * DIVERGENCES.md under "Structural eliminations".
 *
 * Returns NULL only on allocation failure. */
char *cjson_modes_construct(long count, const char *name, const char *raw,
                            const unsigned char *payload, size_t payload_len);

/* The two in-place SETTERS (LESSONS #26): cJSON_SetValuestring and
 * cJSON_SetNumberHelper. `num` is the double to set, `key` selects a target
 * inside `json` (case-sensitively), and `newstr` is the replacement string.
 *
 * Both setters run against the looked-up document item AND against freshly
 * built nodes, so every guard each one has is reachable from one input: a
 * missing target (the C's `object == NULL` check), a non-string target, a NULL
 * replacement, and both sides of cJSON_SetValuestring's
 * `strlen(new) <= strlen(old)` branch.
 *
 * Three of the C's behaviors here are deliberately NOT reachable from this
 * mode, and each is recorded rather than quietly avoided:
 *
 *   - `cJSON_SetNumberHelper(NULL, d)` dereferences without a NULL check
 *     (cJSON.c:385; only the cJSON_SetNumberValue MACRO guards it). That is a
 *     NULL-deref in the ORACLE, which has no defined answer to compare
 *     against, so the call is made only for a non-NULL target. The port has no
 *     null item at all — see DIVERGENCES.md, "Structural eliminations".
 *   - `cJSON_SetValuestring(item, item->valuestring + k)` is an OVERLAPPING
 *     strcpy (cJSON.c:418) — undefined behavior, and ASan reports it as
 *     `memcpy-param-overlap` (spikes/setvaluestring_alias.c). Same reason: UB
 *     in the oracle is not a contract to compare. The port's signature takes
 *     `&mut Value` plus a byte slice, so the aliasing cannot be spelled.
 *   - the `cJSON_IsReference` guard needs a node built by
 *     cJSON_CreateStringReference, which API-COVERAGE.md lists as
 *     out-of-scope: the port never builds a borrowed-pointer node, so the
 *     branch is unreachable rather than untested. A hardcoded `-` on the Rust
 *     side would be a control nothing invokes (LESSONS #31).
 *
 * Returns NULL only on allocation failure; an unparseable `json` is reported
 * in the descriptor (`doc=-`), not as an error, so the setters still run. */
char *cjson_modes_set(double num, const char *key, const char *newstr,
                      const char *json, size_t json_len);

#endif /* CJSON_MODES_H */
