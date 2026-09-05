/* Spike 3: the latent corruption from spike 2, one operation later.
 * A's child->prev is cJSON's "last item" cache. After the bogus detach it
 * points into B, so the NEXT append to A is spliced onto B instead. */
#include <stdio.h>
#include "cJSON.h"

static void show(const char *tag, cJSON *arr) {
    char *p = cJSON_PrintUnformatted(arr);
    printf("%-12s size=%d  print=%s\n", tag, cJSON_GetArraySize(arr), p ? p : "(null)");
    cJSON_free(p);
}

int main(void) {
    cJSON *a = cJSON_Parse("[10,20]");
    cJSON *b = cJSON_Parse("[91,92]");
    cJSON *stolen = cJSON_DetachItemViaPointer(a, cJSON_GetArrayItem(b, 1));
    cJSON_Delete(stolen);

    printf("now append 777 to A:\n");
    cJSON_AddItemToArray(a, cJSON_CreateNumber(777));
    show("A", a);
    show("B", b);

    printf("\nteardown: delete A, then B\n");
    cJSON_Delete(a);
    cJSON_Delete(b);
    printf("clean teardown\n");
    return 0;
}
