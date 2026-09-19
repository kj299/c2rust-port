/* MUTATION-API-SPIKE.md H1, the SAFE half — what the four index/key-based
 * detach entry points actually do, executed rather than reasoned about.
 *
 * H1 showed that cJSON_DetachItemViaPointer never checks that `item` is a child
 * of `parent`, and that two valid public-API pointers can drive it into a NULL
 * write. The four entry points that REACH it — DetachItemFrom{Array,Object,
 * ObjectCaseSensitive} and the Delete wrappers — look the item up inside the
 * parent first, so that missing check is satisfied by construction. This program
 * is the evidence for that claim and for every behavioral note in the
 * `dom-mutate-remove` module (LESSONS #38: a hazard called benign by reading is
 * the one that turns out to be wrong).
 *
 * What it demonstrates, all of it surprising enough to be worth pinning:
 *
 *   Q1  DetachItemFromArray on an OBJECT works — get_array_item has no type
 *       check, so index 0 takes the first MEMBER, and the detached node keeps
 *       that member's key.
 *   Q4  Detaching the first / middle / last / only element each leave a list
 *       whose next append still lands at the END. `child->prev` is cJSON's
 *       last-item cache, and this is the invariant H1b corrupts when the
 *       membership check is skipped.
 *   Q5  Duplicate keys resolve to the first match, so detaching twice removes
 *       both.
 *   Q6  DetachItemFromObject is case-INsensitive; the CaseSensitive twin is not.
 *   Q7  A negative or out-of-range index answers NULL and changes nothing.
 *   Q12 Deleting a missing key is cJSON_Delete(NULL), a documented no-op.
 *
 * Unlike the other three spikes here, this one is EXPECTED TO EXIT 0 — it
 * documents correct behavior the port must reproduce, not a defect. Run under
 * ASan+UBSan by spikes/run.sh; a clean exit is the result.
 */
#include <stdio.h>
#include <string.h>
#include "cJSON.h"

static void show(const char *label, cJSON *doc) {
    char *p = doc ? cJSON_PrintUnformatted(doc) : NULL;
    printf("    %-22s size=%2d  %s\n", label, doc ? cJSON_GetArraySize(doc) : -1,
           p ? p : "(null)");
    cJSON_free(p);
}
static void got(const char *label, cJSON *item) {
    char *p = item ? cJSON_PrintUnformatted(item) : NULL;
    printf("    %-22s %s   (key=%s)\n", label, p ? p : "NULL",
           (item && item->string) ? item->string : "-");
    cJSON_free(p);
}

int main(void) {
    cJSON *d; cJSON *r;

    printf("Q1 DetachItemFromArray on an OBJECT (no type check?)\n");
    d = cJSON_Parse("{\"a\":1,\"b\":2}");
    r = cJSON_DetachItemFromArray(d, 0);
    got("  detached", r); show("  doc after", d);
    cJSON_Delete(r); cJSON_Delete(d);

    printf("Q2 DetachItemFromArray on a SCALAR\n");
    d = cJSON_Parse("7");
    r = cJSON_DetachItemFromArray(d, 0);
    got("  detached", r); show("  doc after", d);
    cJSON_Delete(r); cJSON_Delete(d);

    printf("Q3 DetachItemFromObject on an ARRAY\n");
    d = cJSON_Parse("[1,2,3]");
    r = cJSON_DetachItemFromObject(d, "k");
    got("  detached", r); show("  doc after", d);
    cJSON_Delete(r); cJSON_Delete(d);

    printf("Q4 detach FIRST of 2, then append: does the append land at the end?\n");
    d = cJSON_Parse("[10,20]");
    r = cJSON_DetachItemFromArray(d, 0);
    cJSON_Delete(r);
    show("  after detach[0]", d);
    cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
    show("  after append 99", d);
    cJSON_Delete(d);

    printf("Q4b detach LAST of 3, then append\n");
    d = cJSON_Parse("[10,20,30]");
    r = cJSON_DetachItemFromArray(d, 2); cJSON_Delete(r);
    show("  after detach[2]", d);
    cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
    show("  after append 99", d);
    cJSON_Delete(d);

    printf("Q4c detach MIDDLE of 3, then append\n");
    d = cJSON_Parse("[10,20,30]");
    r = cJSON_DetachItemFromArray(d, 1); cJSON_Delete(r);
    show("  after detach[1]", d);
    cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
    show("  after append 99", d);
    cJSON_Delete(d);

    printf("Q5 duplicate keys: detach twice\n");
    d = cJSON_Parse("{\"k\":1,\"k\":2}");
    r = cJSON_DetachItemFromObject(d, "k"); got("  1st", r); cJSON_Delete(r);
    show("  doc", d);
    r = cJSON_DetachItemFromObject(d, "k"); got("  2nd", r); cJSON_Delete(r);
    show("  doc", d);
    cJSON_Delete(d);

    printf("Q6 case sensitivity\n");
    d = cJSON_Parse("{\"K\":1}");
    r = cJSON_DetachItemFromObject(d, "k"); got("  insensitive k", r); cJSON_Delete(r);
    cJSON_Delete(d);
    d = cJSON_Parse("{\"K\":1}");
    r = cJSON_DetachItemFromObjectCaseSensitive(d, "k"); got("  sensitive k", r); cJSON_Delete(r);
    cJSON_Delete(d);

    printf("Q7 index guards\n");
    d = cJSON_Parse("[1,2]");
    r = cJSON_DetachItemFromArray(d, -1);  got("  which=-1", r); cJSON_Delete(r);
    r = cJSON_DetachItemFromArray(d, 5);   got("  which=5", r);  cJSON_Delete(r);
    show("  doc unchanged", d);
    cJSON_Delete(d);

    printf("Q10 empty containers\n");
    d = cJSON_Parse("[]");
    r = cJSON_DetachItemFromArray(d, 0); got("  [] idx0", r); cJSON_Delete(r);
    cJSON_Delete(d);
    d = cJSON_Parse("{}");
    r = cJSON_DetachItemFromObject(d, "k"); got("  {} key k", r); cJSON_Delete(r);
    cJSON_Delete(d);

    printf("Q11 detach the ONLY element then append\n");
    d = cJSON_Parse("[42]");
    r = cJSON_DetachItemFromArray(d, 0); cJSON_Delete(r);
    show("  after", d);
    cJSON_AddItemToArray(d, cJSON_CreateNumber(99));
    show("  after append", d);
    cJSON_Delete(d);

    printf("Q12 DeleteItemFromObject on a missing key (Delete(NULL) safe?)\n");
    d = cJSON_Parse("{\"a\":1}");
    cJSON_DeleteItemFromObject(d, "zz");
    show("  doc", d);
    cJSON_Delete(d);

    printf("Q13 detached object member keeps its key; nested container detach\n");
    d = cJSON_Parse("{\"o\":{\"x\":1,\"y\":2}}");
    cJSON *inner = cJSON_GetObjectItemCaseSensitive(d, "o");
    r = cJSON_DetachItemFromObject(inner, "x"); got("  detached from inner", r); cJSON_Delete(r);
    show("  doc", d);
    cJSON_Delete(d);
    return 0;
}
