/* Spike: does cJSON_DetachItemViaPointer verify that `item` is a child of
 * `parent`? Reading cJSON.c:2199 says no -- it unlinks `item` from whatever
 * list it is in, then writes through `parent->child` unconditionally in the
 * "last element" branch. Both arguments below are valid, live, non-NULL cJSON
 * pointers from the public API. */
#include <stdio.h>
#include "cJSON.h"

int main(void) {
    /* A: an EMPTY array (parent->child == NULL). */
    cJSON *a = cJSON_CreateArray();
    /* B: a separate array with one item, so that item->next == NULL. */
    cJSON *b = cJSON_CreateArray();
    cJSON_AddItemToArray(b, cJSON_CreateNumber(1));
    cJSON *victim = cJSON_GetArrayItem(b, 0);

    printf("a->child = %p (empty array)\n", (void *)a->child);
    printf("victim   = %p, victim->next = %p (last in B)\n",
           (void *)victim, (void *)victim->next);
    fflush(stdout);

    printf("calling cJSON_DetachItemViaPointer(a, victim) ...\n");
    fflush(stdout);
    cJSON *got = cJSON_DetachItemViaPointer(a, victim);
    printf("survived, got = %p\n", (void *)got);
    return 0;
}
