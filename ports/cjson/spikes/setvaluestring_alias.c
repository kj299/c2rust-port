/* FLAW-SCAN.md L4 — cJSON_SetValuestring's overlapping strcpy (cJSON.c:418).
 *
 * The "new string is no longer than the old" fast path is
 *
 *     if (strlen(valuestring) <= strlen(object->valuestring))
 *     {
 *         strcpy(object->valuestring, valuestring);
 *
 * and nothing stops `valuestring` pointing INTO `object->valuestring`. Stripping
 * a prefix in place — `cJSON_SetValuestring(item, item->valuestring + 2)` — is a
 * plausible call, and it is an overlapping copy: undefined behavior per
 * C17 7.24.2.3 ("If copying takes place between objects that overlap, the
 * behavior is undefined"), which strcpy inherits via its restrict-qualified
 * parameters. Both arguments are valid, live pointers obtained from the public
 * API; no cast or internal field poking is needed.
 *
 * Expected under -fsanitize=address (the exact interceptor named depends on how
 * the compiler lowered the fortified strcpy — `strcpy-param-overlap` at -O1,
 * `memcpy-param-overlap` at -O2; the ranges and the frame are the same):
 *
 *     ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges
 *       [0x...10,0x...33) and [0x...12, 0x...35) overlap
 *       #1 strcpy /usr/include/x86_64-linux-gnu/bits/string_fortified.h:79
 *       #2 cJSON_SetValuestring c/cJSON.c:418
 *
 * The port designs this out rather than checking for it: its signature is
 * `set_valuestring(&mut Value, Option<&[u8]>)`, so the target is exclusively
 * borrowed for the call and the replacement cannot be a view into it — naming
 * both at once does not compile. Recorded in DIVERGENCES.md under "Structural
 * eliminations" because a differential cannot see it: the C's answer here is
 * undefined behavior, not a value (LESSONS #36).
 *
 * Committed because LESSONS #38 says a hazard is only "ran:" once its
 * reproducer is in the repo: the spike's H6 READ this line, checked the
 * destination buffer was long enough, and called it memory-safe. This program is
 * the ten lines that would have shown otherwise.
 *
 * NOTE on the exact-self-assignment case, `SetValuestring(x, x->valuestring)`:
 * it is the same UB by the letter of the standard (the objects overlap
 * completely), but ASan does not flag src == dst, so this spike does not claim
 * it. Only the offset alias below is demonstrated.
 */
#include <stdio.h>
#include "cJSON.h"

int main(void) {
    cJSON *item = cJSON_CreateString("0123456789abcdefghijklmnopqrstuvwxyz");
    if (item == NULL) {
        return 1;
    }
    printf("before: %s\n", item->valuestring);
    fflush(stdout);

    /* strip the first two bytes, in place — the aliasing call */
    char *r = cJSON_SetValuestring(item, item->valuestring + 2);

    printf("after : %s (returned %s the item's own buffer)\n",
           r ? r : "(null)",
           (r == item->valuestring) ? "==" : "!=");
    cJSON_Delete(item);
    return 0;
}
