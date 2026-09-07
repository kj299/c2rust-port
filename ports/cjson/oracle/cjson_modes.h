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

/* The REMOVAL surface -- cJSON_DetachItemFrom{Array,Object,ObjectCaseSensitive}
 * and cJSON_DeleteItemFrom{Array,Object,ObjectCaseSensitive} -- driven as a
 * PROGRAM rather than a single shot.
 *
 * `ops` is a newline-separated list of `<opcode>\t<selector>\t<arg>` lines, at
 * most CJSON_SEQ_MAX_OPS of them; the rest are ignored so the descriptor stays
 * bounded whatever the fuzzer sends. The descriptor is emitted after EVERY step,
 * not only at the end, which is the whole reason this mode exists: cJSON's
 * detach rewires a doubly-linked child list whose `child->prev` doubles as the
 * last-item cache, and a corruption there is invisible until some LATER,
 * unrelated operation uses it (MUTATION-API-SPIKE.md H1b). A mode that compared
 * only the final state would report MATCH on exactly the bug it exists to find.
 *
 *   opcode  entry point
 *   ------  ---------------------------------------------------
 *   da      cJSON_DetachItemFromArray(target, <arg as index>)
 *   xa      cJSON_DeleteItemFromArray(target, <arg as index>)
 *   do      cJSON_DetachItemFromObject(target, <arg>)             case-INsensitive
 *   dos     cJSON_DetachItemFromObjectCaseSensitive(target, <arg>)
 *   xo      cJSON_DeleteItemFromObject(target, <arg>)             case-INsensitive
 *   xos     cJSON_DeleteItemFromObjectCaseSensitive(target, <arg>)
 *   app     cJSON_AddItemToArray(target, cJSON_CreateNumber(<arg>))
 *
 * `app` is the WITNESS op, not a ported entry point -- it is how a corrupted
 * last-item cache becomes visible, since an append is what CONSUMES it
 * (LESSONS #39: a value-comparing differential never touches state no output
 * depends on, so the mode has to contain the operation that reads it). Probed:
 * detaching the first, middle, last or only element all leave a list whose next
 * append still lands at the end.
 *
 * `selector` is empty for the root, else a case-sensitive key of the root
 * object, so ops can reach one level down. Deliberate limits, both stated rather
 * than left to be discovered:
 *   - deeper nesting is not directly addressable. Adding a path grammar would
 *     put the port's own tree walk on trial instead of the C's list surgery,
 *     which is what this module is for.
 *   - `app` runs only when the target is an ARRAY. The C has no such check and
 *     will happily hang a child off a scalar or give an object a NULL-keyed
 *     member; the port can represent neither. That is the `scalar-parent-child`
 *     divergence class, which belongs to cJSON_AddItemTo* and is tracked as its
 *     own increment -- see DIVERGENCES.md. Refusing it HERE keeps this module's
 *     ledger to the removal surface; it is a scope decision, and it is written
 *     down because an unstated one is indistinguishable from an oversight.
 *
 * The detach entry points hand the caller OWNERSHIP of the removed node, so
 * every one printed here is cJSON_Delete'd immediately afterwards.
 *
 * Returns NULL when `json` does not parse (there is nothing to mutate) or on
 * allocation failure. */
#define CJSON_SEQ_MAX_OPS 8
char *cjson_modes_seq(const char *json, size_t json_len,
                      const char *ops, size_t ops_len);

#endif /* CJSON_MODES_H */
