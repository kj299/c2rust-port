/* SPIKE: the non-container parent (`scalar-parent-child`).
 *
 * cJSON's add_item_to_array (cJSON.c:1973) guards exactly three things: a NULL
 * item, a NULL parent, and self-reference. It never asks whether the parent is
 * a container. add_item_to_object adds a NULL-key guard and then delegates to
 * it. So every public Add* entry point will hang a child off a number, a
 * string, a bool or a null, and will give an OBJECT a member with a NULL key.
 *
 * Three modules (dom-mutate-{remove,place} and dom-construct) declined to put
 * this on the compared contract and said so. This spike is the evidence base
 * for doing it: it establishes what the C actually does, so the port's
 * divergence is measured against behaviour that was RUN, not read
 * (LESSONS #38).
 *
 * Expected: clean exit 0 under ASan+UBSan+LSan. Every finding here is a
 * behavioural surprise, not a memory error -- which is itself the result.
 */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"

static void line(const char *h) { printf("\n--- %s\n", h); }

/* Print a node and its "container view" -- the two disagree for a malformed
 * tree, and that disagreement is the whole point. */
static void show(const char *what, cJSON *n) {
    char *p = cJSON_PrintUnformatted(n);
    printf("  %-28s print=%-22s size=%d\n",
           what, p ? p : "(null)", cJSON_GetArraySize(n));
    cJSON_free(p);
}

/* H1: a child hung off every scalar type. */
static void h1_child_on_scalars(void) {
    line("H1  child hung off a scalar (cJSON_AddItemToArray, no type check)");
    struct { const char *name; cJSON *(*make)(void); } kinds[] = {
        {"number", NULL}, {"string", NULL}, {"true", NULL},
        {"false", NULL}, {"null", NULL}, {"raw", NULL},
    };
    (void)kinds;
    cJSON *nodes[6];
    const char *names[6] = {"number", "string", "true", "false", "null", "raw"};
    nodes[0] = cJSON_CreateNumber(7);
    nodes[1] = cJSON_CreateString("s");
    nodes[2] = cJSON_CreateTrue();
    nodes[3] = cJSON_CreateFalse();
    nodes[4] = cJSON_CreateNull();
    nodes[5] = cJSON_CreateRaw("RAW");

    for (int i = 0; i < 6; i++) {
        cJSON_bool ok = cJSON_AddItemToArray(nodes[i], cJSON_CreateNumber(99));
        printf("  add->%-7s rc=%d", names[i], ok ? 1 : 0);
        char *p = cJSON_PrintUnformatted(nodes[i]);
        cJSON *got = cJSON_GetArrayItem(nodes[i], 0);
        char *gp = got ? cJSON_PrintUnformatted(got) : NULL;
        printf("  print=%-8s size=%d  item[0]=%s\n",
               p ? p : "(null)", cJSON_GetArraySize(nodes[i]),
               gp ? gp : "NULL");
        cJSON_free(gp);
        cJSON_free(p);
        cJSON_Delete(nodes[i]);   /* does Delete free the hung child? LSan says */
    }
}

/* H2: AddItemToArray onto an OBJECT makes a member with a NULL key. The two
 * lookup functions then disagree, which is the finding worth having. */
static void h2_null_keyed_member(void) {
    line("H2  NULL-keyed object member, and what each lookup does with it");
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "a", 1);
    cJSON_AddItemToArray(obj, cJSON_CreateNumber(2));   /* <- NULL key */
    cJSON_AddNumberToObject(obj, "b", 3);

    show("object with a NULL key", obj);
    printf("  GetObjectItem(\"a\")              = %s   (case-INsensitive)\n",
           cJSON_GetObjectItem(obj, "a") ? "found" : "NULL");
    printf("  GetObjectItem(\"b\")              = %s   <- AFTER the NULL key\n",
           cJSON_GetObjectItem(obj, "b") ? "found" : "NULL");
    printf("  GetObjectItemCaseSensitive(\"a\") = %s\n",
           cJSON_GetObjectItemCaseSensitive(obj, "a") ? "found" : "NULL");
    printf("  GetObjectItemCaseSensitive(\"b\") = %s   <- AFTER the NULL key\n",
           cJSON_GetObjectItemCaseSensitive(obj, "b") ? "found" : "NULL");
    printf("  HasObjectItem(\"b\")              = %s\n",
           cJSON_HasObjectItem(obj, "b") ? "true" : "false");
    printf("  the printed key for a NULL string is \"\" -- but a member keyed\n"
           "  \"\" is a DIFFERENT node: look it up to see.\n");
    printf("  GetObjectItem(\"\")               = %s\n",
           cJSON_GetObjectItem(obj, "") ? "found" : "NULL");
    cJSON_Delete(obj);
}

/* H3: AddItemToObject onto an ARRAY -- a keyed member inside an array. */
static void h3_keyed_member_in_array(void) {
    line("H3  keyed member inside an ARRAY (cJSON_AddItemToObject on an array)");
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(1));
    cJSON_bool ok = cJSON_AddItemToObject(arr, "k", cJSON_CreateNumber(2));
    printf("  rc=%d\n", ok ? 1 : 0);
    show("array carrying a key", arr);
    printf("  the key is stored but print_array never emits it -- round-tripping\n"
           "  through print LOSES it, so print equality hides this state.\n");
    cJSON_Delete(arr);
}

/* H4/H5: does the malformed state survive Duplicate, and what does Compare say? */
static void h4_duplicate_and_compare(void) {
    line("H4  Duplicate of a scalar-with-child, and H5 Compare against a clean one");
    cJSON *n = cJSON_CreateNumber(7);
    cJSON_AddItemToArray(n, cJSON_CreateNumber(99));
    cJSON *dup = cJSON_Duplicate(n, 1 /* recurse */);
    show("original  (number + child)", n);
    show("duplicate", dup);

    cJSON *clean = cJSON_CreateNumber(7);
    printf("  Compare(malformed, clean number 7) = %s\n",
           cJSON_Compare(n, clean, 1) ? "EQUAL" : "not equal");
    printf("  Compare(malformed, its duplicate)  = %s\n",
           cJSON_Compare(n, dup, 1) ? "EQUAL" : "not equal");
    cJSON_Delete(clean);
    cJSON_Delete(dup);
    cJSON_Delete(n);
}

/* H6: the guards that DO exist. */
static void h6_the_guards(void) {
    line("H6  the three guards add_item_to_array actually has");
    cJSON *a = cJSON_CreateArray();
    printf("  AddItemToArray(arr, NULL)      rc=%d  (item NULL)\n",
           cJSON_AddItemToArray(a, NULL) ? 1 : 0);
    printf("  AddItemToArray(NULL, item)     rc=%d  (parent NULL; item leaks on\n"
           "                                        the caller -- freed here)\n",
           cJSON_AddItemToArray(NULL, NULL) ? 1 : 0);
    printf("  AddItemToArray(arr, arr)       rc=%d  (self-reference)\n",
           cJSON_AddItemToArray(a, a) ? 1 : 0);
    cJSON *n = cJSON_CreateNumber(1);
    printf("  AddItemToObject(obj, NULL, it) rc=%d  (NULL key)\n",
           cJSON_AddItemToObject(a, NULL, n) ? 1 : 0);
    cJSON_Delete(n);            /* refused -> still ours */
    cJSON_Delete(a);
}

/* H7: the CONST-key variant onto a scalar, then Delete. AddItemToObjectCS
 * marks the key not-to-be-freed; getting that wrong is a leak or a bad free. */
static void h7_const_key_on_a_scalar(void) {
    line("H7  AddItemToObjectCS onto a scalar, then Delete (const-key free path)");
    cJSON *num = cJSON_CreateNumber(1);
    cJSON_bool ok = cJSON_AddItemToObjectCS(num, "lit", cJSON_CreateNumber(2));
    printf("  rc=%d\n", ok ? 1 : 0);
    show("number with a CS-keyed child", num);
    cJSON_Delete(num);          /* must not free the string literal */
    printf("  deleted without freeing the literal (ASan would have said otherwise)\n");
}

/* H8: nested -- a malformed scalar sitting inside a well-formed array. */
static void h8_nested_in_a_real_array(void) {
    line("H8  the malformed scalar nested inside a REAL array");
    cJSON *arr = cJSON_CreateArray();
    cJSON *num = cJSON_CreateNumber(7);
    cJSON_AddItemToArray(num, cJSON_CreateNumber(99));   /* malform it first */
    cJSON_AddItemToArray(arr, num);
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(8));
    show("array containing it", arr);
    printf("  the array prints 2 elements and the hung child is invisible,\n"
           "  but GetArraySize(item[0]) still reports it:  %d\n",
           cJSON_GetArraySize(cJSON_GetArrayItem(arr, 0)));
    cJSON_Delete(arr);
}

int main(void) {
    printf("cJSON %s -- scalar-parent-child spike\n", cJSON_Version());
    h1_child_on_scalars();
    h2_null_keyed_member();
    h3_keyed_member_in_array();
    h4_duplicate_and_compare();
    h6_the_guards();
    h7_const_key_on_a_scalar();
    h8_nested_in_a_real_array();
    printf("\nspike complete\n");
    return 0;
}
