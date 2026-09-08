/* What cJSON's PLACEMENT entry points actually do — executed, not inferred.
 *
 * Companion to spikes/detach_relink.c, for module 14 (`dom-mutate-place`).
 * LESSONS #38: this directory exists because the one hazard the mutation spike
 * reasoned about instead of running is the one it got wrong, so every claim
 * `dom.rs` and `cjson_modes.h` make about cJSON_InsertItemInArray and
 * cJSON_ReplaceItemIn* is re-derivable here.
 *
 * Expected to exit 0 under ASan+UBSan+LSan: like detach_relink.c, this one
 * documents behavior that is CORRECT, not a defect. Two of the behaviors are
 * merely surprising:
 *
 *   I1  cJSON_InsertItemInArray with an index past the end does NOT fail. The
 *       C looks the position up with get_array_item, and NULL sends it to
 *       add_item_to_array — so it appends and returns true.
 *   R4  cJSON_ReplaceItemInObject rewrites the replacement's key to the LOOKUP
 *       string before it looks anything up. A case-insensitive replace of "a"
 *       in {"A":1} therefore leaves {"a":...}, and a FAILED replace has still
 *       overwritten the caller's node->string.
 *
 * And one is an ownership rule with teeth: insert and replace adopt the new
 * node only on SUCCESS. On every failure path the caller still owns it. The
 * first draft of this program leaked exactly there — LeakSanitizer named
 * cJSON_New_Item under the `which < 0` case — which is why the failure paths
 * below all free explicitly.
 *
 * The relink checks matter because cJSON's `child->prev` doubles as a last-item
 * cache that nothing printable depends on (LESSONS #39). Every case that
 * rewires the list therefore APPENDS afterwards and checks where the value
 * landed: that append is the only operation that reads the cache back.
 */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"

static int fails = 0;

static void expect(const char *what, cJSON *doc, const char *want) {
    char *got = doc ? cJSON_PrintUnformatted(doc) : NULL;
    int ok = got && strcmp(got, want) == 0;
    printf("  %-4s %-34s %s\n", ok ? "ok" : "FAIL", what, got ? got : "(null)");
    if (!ok) {
        printf("       wanted: %s\n", want);
        fails = 1;
    }
    cJSON_free(got);
}

static void expect_int(const char *what, int got, int want) {
    int ok = (got == want);
    printf("  %-4s %-34s %d\n", ok ? "ok" : "FAIL", what, got);
    if (!ok) {
        printf("       wanted: %d\n", want);
        fails = 1;
    }
}

int main(void) {
    cJSON *d, *t, *n;

    printf("I1 insert past the end APPENDS, it does not fail\n");
    d = cJSON_Parse("[1,2]");
    expect_int("returns true", cJSON_InsertItemInArray(d, 99, cJSON_CreateNumber(7)), 1);
    expect("appended", d, "[1,2,7]");
    cJSON_Delete(d);

    printf("I2 insert at each position, then append (last-item cache)\n");
    {
        const int at[] = {0, 1, 2};
        const char *after[] = {"[7,10,20]", "[10,7,20]", "[10,20,7]"};
        const char *appended[] = {"[7,10,20,99]", "[10,7,20,99]", "[10,20,7,99]"};
        for (int i = 0; i < 3; i++) {
            d = cJSON_Parse("[10,20]");
            cJSON_InsertItemInArray(d, at[i], cJSON_CreateNumber(7));
            expect("after insert", d, after[i]);
            cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
            expect("  append lands at the end", d, appended[i]);
            cJSON_Delete(d);
        }
    }

    printf("I3 insert into an empty array starts a fresh list\n");
    d = cJSON_Parse("[]");
    cJSON_InsertItemInArray(d, 0, cJSON_CreateNumber(7));
    expect("inserted", d, "[7]");
    cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
    expect("  append lands at the end", d, "[7,99]");
    cJSON_Delete(d);

    printf("I4 the guards, and who owns the node when they fire\n");
    d = cJSON_Parse("[1,2]");
    n = cJSON_CreateNumber(8);
    expect_int("which < 0 -> false", cJSON_InsertItemInArray(d, -1, n), 0);
    cJSON_Delete(n);                 /* the caller still owns it — see the header */
    expect_int("newitem NULL -> false", cJSON_InsertItemInArray(d, 0, NULL), 0);
    expect("document untouched", d, "[1,2]");
    cJSON_Delete(d);

    printf("R1 replace at each position, then append\n");
    {
        const char *after[] = {"[\"X\",20,30]", "[10,\"X\",30]", "[10,20,\"X\"]"};
        const char *appended[] = {"[\"X\",20,30,99]", "[10,\"X\",30,99]", "[10,20,\"X\",99]"};
        for (int i = 0; i < 3; i++) {
            d = cJSON_Parse("[10,20,30]");
            cJSON_ReplaceItemInArray(d, i, cJSON_CreateString("X"));
            expect("after replace", d, after[i]);
            cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
            expect("  append lands at the end", d, appended[i]);
            cJSON_Delete(d);
        }
    }

    printf("R2 replacing the ONLY element (prev == self branch)\n");
    d = cJSON_Parse("[42]");
    cJSON_ReplaceItemInArray(d, 0, cJSON_CreateString("X"));
    expect("replaced", d, "[\"X\"]");
    cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
    expect("  append lands at the end", d, "[\"X\",99]");
    cJSON_Delete(d);

    printf("R3 replace guards (an out-of-range index IS a failure here)\n");
    d = cJSON_Parse("[1]");
    n = cJSON_CreateNumber(5);
    expect_int("which = 9 -> false", cJSON_ReplaceItemInArray(d, 9, n), 0);
    cJSON_Delete(n);
    n = cJSON_CreateNumber(5);
    expect_int("which = -1 -> false", cJSON_ReplaceItemInArray(d, -1, n), 0);
    cJSON_Delete(n);
    expect("document untouched", d, "[1]");
    cJSON_Delete(d);
    d = cJSON_Parse("[]");
    n = cJSON_CreateNumber(5);
    expect_int("empty container -> false", cJSON_ReplaceItemInArray(d, 0, n), 0);
    cJSON_Delete(n);
    cJSON_Delete(d);

    printf("R4 ReplaceItemInObject rewrites the key to the LOOKUP string\n");
    d = cJSON_Parse("{\"a\":1,\"b\":2,\"c\":3}");
    cJSON_ReplaceItemInObject(d, "b", cJSON_CreateString("X"));
    expect("slot kept, not moved to the end", d, "{\"a\":1,\"b\":\"X\",\"c\":3}");
    cJSON_Delete(d);

    d = cJSON_Parse("{\"A\":1}");
    cJSON_ReplaceItemInObject(d, "a", cJSON_CreateString("X"));
    expect("case-INsensitive replace RENAMES", d, "{\"a\":\"X\"}");
    cJSON_Delete(d);

    d = cJSON_Parse("{\"A\":1}");
    n = cJSON_CreateString("X");
    expect_int("case-sensitive finds nothing", cJSON_ReplaceItemInObjectCaseSensitive(d, "a", n), 0);
    expect("document untouched", d, "{\"A\":1}");
    /* ...but the replacement was renamed anyway, BEFORE the lookup happened. */
    expect_int("failed replace still renamed it", n->string && strcmp(n->string, "a") == 0, 1);
    cJSON_Delete(n);
    cJSON_Delete(d);

    printf("R5 duplicate keys resolve to the first match\n");
    d = cJSON_Parse("{\"k\":1,\"k\":2}");
    cJSON_ReplaceItemInObject(d, "k", cJSON_CreateString("X"));
    expect("first replaced", d, "{\"k\":\"X\",\"k\":2}");
    cJSON_Delete(d);

    printf("\n%s\n", fails ? "SPIKE FAILED — cJSON behavior differs from what the port assumes"
                           : "all placement behaviors are as the port documents them");
    return fails;
}
