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

/* The REMOVAL and PLACEMENT surfaces -- cJSON_DetachItemFrom{Array,Object,
 * ObjectCaseSensitive}, cJSON_DeleteItemFrom{Array,Object,ObjectCaseSensitive},
 * cJSON_InsertItemInArray and cJSON_ReplaceItemIn{Array,Object,
 * ObjectCaseSensitive} -- driven as a PROGRAM rather than a single shot.
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
 *   ins     cJSON_InsertItemInArray(target, <arg as index>, Number(<arg>))
 *   rep     cJSON_ReplaceItemInArray(target, <arg as index>, Number(<arg>))
 *   ro      cJSON_ReplaceItemInObject(target, <arg>, Number(strlen(<arg>)))   case-INsensitive
 *   ros     cJSON_ReplaceItemInObjectCaseSensitive(target, <arg>, ...)
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
 *   - `app`, `ins` and `rep` run only when the target is an ARRAY. The C has no
 *     such check on any of them and will happily hang a child off a scalar or
 *     give an object a member with a NULL key; the port can represent neither.
 *     The NULL-keyed member is worth spelling out, because an empty key is NOT
 *     the same thing: the C's get_object_item stops its walk at a NULL string,
 *     so a NULL-keyed member is UNFINDABLE, while a member keyed "" is found by
 *     a lookup for "". A `Value::Object` entry has a key either way, so the port
 *     cannot express "present but unfindable". That is the `scalar-parent-child`
 *     class, it belongs to cJSON_AddItemTo*, and it is tracked as its own
 *     increment -- see DIVERGENCES.md. Refusing it HERE is a scope decision, and
 *     it is written down because an unstated one is indistinguishable from an
 *     oversight.
 *   - `ro`/`ros` are NOT restricted, because every way they can fail is
 *     representable: a missing key, a non-object parent and an empty container
 *     all just answer false on both sides.
 *
 * OWNERSHIP, in both directions, because the C splits it across the return
 * value and every path has to be handled by hand:
 *   - the detach entry points hand the caller ownership of the REMOVED node, so
 *     every one printed here is cJSON_Delete'd immediately afterwards;
 *   - insert and replace take ownership of the new node only when they SUCCEED.
 *     On any failure path -- a negative index, a NULL item, a missing key, a
 *     non-container parent -- the caller still owns it and must free it. Probed
 *     the hard way: the first draft of this mode's probe leaked exactly there,
 *     under `cJSON_InsertItemInArray(arr, -1, ...)`, and LeakSanitizer named it.
 *
 * Two placement behaviors worth knowing before reading the descriptor, both
 * executed rather than inferred (spikes/place_relink.c):
 *   - cJSON_InsertItemInArray with an index PAST THE END does not fail. It falls
 *     through to add_item_to_array and APPENDS, so `ins 99` on a 2-element array
 *     succeeds and grows it to 3.
 *   - cJSON_ReplaceItemInObject RENAMES the replacement to the lookup string
 *     before it looks anything up. A case-insensitive replace of `a` in
 *     {"A":1} therefore leaves {"a":"..."} -- the key's spelling changes -- and
 *     even a FAILED replace has already overwritten the caller's node->string.
 *     The port consumes the replacement by value, so there is no caller-visible
 *     node left to have been renamed; recorded in DIVERGENCES.md under
 *     "Structural eliminations" rather than compared.
 *
 * Returns NULL when `json` does not parse (there is nothing to mutate) or on
 * allocation failure. */
#define CJSON_SEQ_MAX_OPS 8
char *cjson_modes_seq(const char *json, size_t json_len,
                      const char *ops, size_t ops_len);

/* The four OPTIONS entry points in one shot (LESSONS #26): cJSON_ParseWithOpts,
 * cJSON_ParseWithLengthOpts, cJSON_PrintBuffered and cJSON_PrintPreallocated.
 *
 * `flags` is a bit set: bit 0 = require_null_terminated (both parsers),
 * bit 1 = format (both printers). `prebuffer` is cJSON_PrintBuffered's, passed
 * through INCLUDING negatives -- that is the one behavior the prebuffer size
 * has (cJSON.c:1278) -- but clamped above at CJSON_OPTS_MAX_BUF so a fuzzer
 * cannot ask for a gigabyte. `prealloc` is cJSON_PrintPreallocated's buffer
 * length, same treatment.
 *
 * `json` must be NUL-terminated at `json_len` (the driver's stdin buffer is):
 * cJSON_ParseWithLengthOpts is given the explicit length and cJSON_ParseWithOpts
 * the pointer, so the two entry points' differing views of the SAME bytes are
 * both on the contract. That difference is the point -- `{"a":1}` with no
 * terminator inside the length is rejected by the length form under
 * require_null_terminated and accepted by the string form, which appends one.
 *
 * What the descriptor carries, and why each field is there rather than implied:
 *
 *   pwl/pwo      the two parses' results, printed, or `-`.
 *   pwlend/pwoend  `*return_parse_end` as an OFFSET from `json`. This is the
 *                whole distinct behavior of the *WithOpts pair and the reason
 *                the mode exists; it is also deliberately NOT the error text,
 *                which stays a documented divergence. Putting it on the
 *                contract immediately found a real port divergence (cJSON's
 *                parse_string rewinds to a pointer set before it validates
 *                anything, so `{bad` reports 2, not 1).
 *   pb           cJSON_PrintBuffered's bytes, length-prefixed.
 *   ppa          cJSON_PrintPreallocated's cJSON_bool at `prealloc`.
 *   ppabuf       the preallocated buffer AFTER the call, hex, having been
 *                memset to 0 before it. Without this the intentional
 *                divergence below is unmeasured, and a control nothing
 *                observes is not a control (LESSONS #31/#40).
 *   ppamin       the SMALLEST buffer length that succeeds, found by scanning.
 *                One number that pins the entire `ensure` predicate, instead
 *                of one sample of it per case. Probed to be `strlen + 2`: the
 *                extra byte over `strlen + 1` is ensure's reserved NUL slot,
 *                and a caller who sizes a buffer the obvious way gets `false`.
 *
 * Each scan step allocates EXACTLY the length it passes, rather than reusing
 * one large buffer, so a write past the stated length is a heap overflow the
 * oracle-sanitize gate will catch instead of silently landing in slack.
 *
 * Two of cJSON_PrintPreallocated's three refusals are not exercised here and
 * both are recorded rather than quietly skipped: `buffer == NULL` and
 * `length < 0` cannot be spelled against the port's `&mut [u8]`, so a Rust-side
 * answer would be a hardcoded constant no code path reaches (LESSONS #31).
 * The negative length IS handled -- by the mode on both sides, which answers
 * false without calling the core -- and that is stated in DIVERGENCES.md under
 * "Structural eliminations" alongside the NULL buffer.
 *
 * Returns NULL only on allocation failure; an unparseable document is reported
 * in the descriptor, not as an error, so the printers' guards still run. */
#define CJSON_OPTS_MAX_BUF 4096
char *cjson_modes_opts(int flags, int prebuffer, int prealloc,
                       const char *json, size_t json_len);

/* The NON-CONTAINER PARENT -- cJSON's add_item_to_array / add_item_to_object
 * applied to a parent that is not the container the function name implies.
 *
 * `add_item_to_array` (cJSON.c:1973) guards exactly three things: a NULL item,
 * a NULL parent, and self-reference. It never asks whether the parent is a
 * container, and `add_item_to_object` only adds a NULL-key guard before
 * delegating to it. So every public Add* entry point will hang a child off a
 * number, a string, a bool or a null, and will give an OBJECT a member whose
 * key is NULL. SCALAR-PARENT-SPIKE.md is the executed evidence.
 *
 * `kind` selects the target: num / str / true / false / null / raw / arr / obj,
 * or `doc` for the parsed document's root -- which is how a FUZZER gets to pick
 * the target's type. `arr` and `obj` are the controls: there the C and the port
 * agree, and a run where they diverge is a port bug rather than this class.
 *
 *   op    entry point                                   (item is Number(99))
 *   ----  --------------------------------------------------------------
 *   a     cJSON_AddItemToArray(target, item)
 *   o     cJSON_AddItemToObject(target, <key>, item)
 *   ocs   cJSON_AddItemToObjectCS(target, <key>, item)   key NOT copied
 *   t     cJSON_AddTrueToObject(target, <key>)
 *   f     cJSON_AddFalseToObject(target, <key>)
 *   z     cJSON_AddNullToObject(target, <key>)
 *   m     cJSON_AddNumberToObject(target, <key>, 5)
 *   s     cJSON_AddStringToObject(target, <key>, "v")
 *
 * The mode brackets the operation with two ORDINARY members, `pre` before and
 * `post` after, added only when the target is already an object (adding one to
 * a number would itself be the malformed operation and would muddle the
 * experiment). `post` is the load-bearing one: see the descriptor below.
 *
 * WHY THE DESCRIPTOR LOOKS LIKE THIS. The spike established that the port's
 * three existing comparison surfaces are all BLIND to this class:
 *
 *   - print ignores a child hung off a non-container (a number still prints
 *     `7`), and print_array silently drops a key stored on an array element;
 *   - cJSON_Compare reports a malformed node EQUAL to a clean one, because it
 *     never examines a non-container's children;
 *   - cJSON_Duplicate copies the hung child, so a dup round-trip matches too.
 *
 * A descriptor built on printed bytes would therefore report MATCH on every
 * case this mode exists to test (LESSONS #39: name the operation that CONSUMES
 * the state no output depends on). So it reports the container view --
 * cJSON_GetArraySize and cJSON_GetArrayItem -- and it reports the two object
 * lookups SEPARATELY, because they disagree:
 *
 *   cJSON_GetObjectItemCaseSensitive stops its walk at a NULL key
 *   (cJSON.c:1910 tests `current_element->string != NULL` in the loop
 *   condition), so a NULL-keyed member makes every member AFTER it unfindable
 *   -- `post` is what detects that. cJSON_GetObjectItem does not stop, because
 *   case_insensitive_strcmp returns 1 for a NULL argument (cJSON.c:135), so it
 *   walks past and still finds `post`. Two functions documented to differ only
 *   in case sensitivity differ in REACHABILITY, and only a descriptor carrying
 *   both can say so.
 *
 * `empty` looks up "" to separate the two states the printed form conflates: a
 * NULL-keyed member PRINTS as `""` but is not findable by "", while a member
 * genuinely keyed "" is. `cmp` and `dupsz` are carried to pin the blindness
 * itself -- they are expected to MATCH, and a ledger that did not show them
 * would be claiming the divergence is wider than it is.
 *
 * Returns NULL only on allocation failure; an unparseable document is reported
 * in the descriptor (`doc=-`), not as an error, so the add still runs. */
char *cjson_modes_parent(const char *kind, const char *op, const char *key,
                         const char *json, size_t json_len);

#endif /* CJSON_MODES_H */
