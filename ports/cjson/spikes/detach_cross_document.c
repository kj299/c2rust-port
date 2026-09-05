/* Spike 2: the same missing membership check with a NON-empty parent A.
 * Detaching B's last item "via pointer" from A splices a pointer from B's
 * list into A's, and unlinks the item from B without B knowing. */
#include <stdio.h>
#include "cJSON.h"

static void show(const char *tag, cJSON *arr) {
    char *p = cJSON_PrintUnformatted(arr);
    printf("%-22s size=%d  print=%s\n", tag, cJSON_GetArraySize(arr), p ? p : "(null)");
    cJSON_free(p);
}

int main(void) {
    cJSON *a = cJSON_Parse("[10,20]");
    cJSON *b = cJSON_Parse("[91,92]");
    show("A before", a);
    show("B before", b);

    cJSON *victim = cJSON_GetArrayItem(b, 1);   /* B's LAST item */
    printf("detaching B's last item, but naming A as the parent...\n");
    cJSON *got = cJSON_DetachItemViaPointer(a, victim);
    printf("returned %p (the API reports success)\n", (void *)got);

    show("A after", a);
    show("B after", b);
    cJSON_Delete(got);
    cJSON_Delete(b);
    cJSON_Delete(a);
    return 0;
}
