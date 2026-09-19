/* The C side's builder/query modes, as a library.
 *
 * Both the differential driver (`driver.c`, an executable diff_run runs) and the
 * ABI shim (`../ffi/shim.c`, compiled into libcjson_c.so for lib_diff) need this
 * exact behavior. Implementing it twice would let the two drift and each still
 * look green — the same trap the Rust side had between `crates/driver` and the
 * probe glue, fixed the same way: one implementation, two thin callers.
 *
 * Both entry points return a malloc'd NUL-terminated string the caller frees,
 * or NULL on failure.
 *
 * These modes put the builder/query/accessor API on the compared contract at
 * all (LESSONS #26): a gate judges only the surface the driver exposes, and an
 * accessor no mode calls is ungated whatever the matrix says.
 */
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cjson_modes.h"

/* Fixed-order predicate flags: one letter per cJSON_Is* that answers true. */
static void append_flags(char *buf, size_t cap, const cJSON *it) {
    char f[16];
    size_t n = 0;
    if (cJSON_IsInvalid(it)) f[n++] = 'I';
    if (cJSON_IsNull(it))    f[n++] = 'N';
    if (cJSON_IsFalse(it))   f[n++] = 'F';
    if (cJSON_IsTrue(it))    f[n++] = 'T';
    if (cJSON_IsBool(it))    f[n++] = 'B';
    if (cJSON_IsNumber(it))  f[n++] = 'M';
    if (cJSON_IsString(it))  f[n++] = 'S';
    if (cJSON_IsRaw(it))     f[n++] = 'R';
    if (cJSON_IsArray(it))   f[n++] = 'A';
    if (cJSON_IsObject(it))  f[n++] = 'O';
    f[n] = '\0';
    strncat(buf, f, cap - strlen(buf) - 1);
}

char *cjson_modes_build(const char *variant) {
    cJSON *root = NULL;
    if (strcmp(variant, "flat") == 0) {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "s", "hi");
        cJSON_AddNumberToObject(root, "n", 42);
        cJSON_AddBoolToObject(root, "t", 1);
        cJSON_AddBoolToObject(root, "f", 0);
        cJSON_AddNullToObject(root, "z");
    } else if (strcmp(variant, "array") == 0) {
        root = cJSON_CreateArray();
        cJSON_AddItemToArray(root, cJSON_CreateNumber(1));
        cJSON_AddItemToArray(root, cJSON_CreateString("two"));
        cJSON_AddItemToArray(root, cJSON_CreateTrue());
        cJSON_AddItemToArray(root, cJSON_CreateNull());
    } else if (strcmp(variant, "nested") == 0) {
        root = cJSON_CreateObject();
        cJSON *arr = cJSON_CreateArray();
        cJSON *inner = cJSON_CreateObject();
        cJSON_AddNumberToObject(inner, "deep", -1);
        cJSON_AddItemToArray(arr, inner);
        cJSON_AddItemToObject(root, "arr", arr);
    } else if (strcmp(variant, "numbers") == 0) {
        root = cJSON_CreateArray();
        cJSON_AddItemToArray(root, cJSON_CreateNumber(0));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(-1));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(0.1));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(1e308));
        cJSON_AddItemToArray(root, cJSON_CreateNumber(1.0 / 0.0));  /* inf */
    } else if (strcmp(variant, "dupkey") == 0) {
        /* probed: the same key twice APPENDS, it does not replace */
        root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "k", 1);
        cJSON_AddNumberToObject(root, "k", 2);
    } else if (strcmp(variant, "add-null") == 0) {
        /* probed: adding a NULL item is silently ignored */
        root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "a", NULL);
        cJSON_AddNumberToObject(root, "b", 1);
    } else if (strcmp(variant, "empty") == 0) {
        root = cJSON_CreateObject();
    } else if (strcmp(variant, "strings") == 0) {
        root = cJSON_CreateArray();
        cJSON_AddItemToArray(root, cJSON_CreateString(""));
        cJSON_AddItemToArray(root, cJSON_CreateString("a\"b\\c"));
        cJSON_AddItemToArray(root, cJSON_CreateString("tab\there"));
    } else {
        return NULL;
    }
    if (root == NULL) return NULL;
    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (printed == NULL) return NULL;
    /* hand back plain malloc memory so the caller frees with free() regardless
     * of which allocator cJSON was built with */
    char *out = strdup(printed);
    cJSON_free(printed);
    return out;
}

/* A double, encoded so the two sides cannot disagree for FORMATTING reasons.
 * printf("%g"/"%.17g") is a portability trap between C and Rust — the compared
 * contract would then be "libc's float formatter", not the accessor. The raw
 * IEEE-754 bits are exact and identical on both sides. NaN is spelled out
 * because cJSON_GetNumberValue RETURNS NaN for every non-number (including
 * NULL), so it is the common answer here, not an edge case — and NaN has many
 * bit patterns but only one meaning. */
static void append_double(char *buf, size_t cap, double d) {
    char t[32];
    if (isnan(d)) {
        snprintf(t, sizeof t, "nan");
    } else {
        uint64_t bits;
        memcpy(&bits, &d, sizeof bits);
        snprintf(t, sizeof t, "%016llx", (unsigned long long)bits);
    }
    strncat(buf, t, cap - strlen(buf) - 1);
}

char *cjson_modes_access(const char *key, int index,
                         const char *json, size_t json_len) {
    cJSON *root = cJSON_ParseWithLength(json, json_len);
    if (root == NULL) return NULL;

    /* CASE-INSENSITIVE by definition (cJSON.c: get_object_item(.., false)) —
     * that is the whole difference from the `query` mode's lookup. */
    cJSON *by_key = cJSON_GetObjectItem(root, key);
    int has = cJSON_HasObjectItem(root, key) ? 1 : 0;
    /* index < 0 short-circuits to NULL inside cJSON_GetArrayItem; the driver
     * passes the fuzzer's int straight through so that branch is reachable. */
    cJSON *by_idx = cJSON_GetArrayItem(root, index);

    /* Fed the lookup results deliberately, NULL included: both accessors route
     * through cJSON_IsString/cJSON_IsNumber, which answer false for NULL, so
     * NULL-tolerance is contract and belongs on the compared surface. */
    const char *skey = cJSON_GetStringValue(by_key);
    const char *sidx = cJSON_GetStringValue(by_idx);
    double nkey = cJSON_GetNumberValue(by_key);
    double nidx = cJSON_GetNumberValue(by_idx);

    char *pkey = by_key ? cJSON_PrintUnformatted(by_key) : NULL;
    char *pidx = by_idx ? cJSON_PrintUnformatted(by_idx) : NULL;

    size_t cap = 256
               + (pkey ? strlen(pkey) : 1) + (pidx ? strlen(pidx) : 1)
               + (skey ? strlen(skey) : 1) + (sidx ? strlen(sidx) : 1);
    char *out = (char *)malloc(cap);
    if (out != NULL) {
        int n = snprintf(out, cap, "has=%d;kobj=%s;kstr=%s;knum=", has,
                         pkey ? pkey : "-", skey ? skey : "-");
        if (n < 0 || (size_t)n >= cap) { free(out); out = NULL; }
    }
    if (out != NULL) {
        append_double(out, cap, nkey);
        size_t n = strlen(out);
        snprintf(out + n, cap - n, ";iarr=%s;istr=%s;inum=",
                 pidx ? pidx : "-", sidx ? sidx : "-");
        append_double(out, cap, nidx);
    }

    cJSON_free(pkey);
    cJSON_free(pidx);
    cJSON_Delete(root);
    return out;
}

/* ---- `construct` mode: the 12 constructor entry points -------------------- */

/* A bounds-checked appender. The descriptor mixes attacker-controlled bytes
 * (the key, the raw text, every string element) with fixed structure, so every
 * write is length-checked and a single overflow poisons the whole buffer rather
 * than silently truncating one field into another. */
struct sbuf {
    char *p;
    size_t cap;
    size_t len;
    int ok;
};

static void sb_add(struct sbuf *b, const char *s, size_t n) {
    if (!b->ok || n > b->cap - b->len - 1) {
        b->ok = 0;
        return;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = '\0';
}

static void sb_str(struct sbuf *b, const char *s) { sb_add(b, s, strlen(s)); }

static void sb_int(struct sbuf *b, long v) {
    char t[32];
    int n = snprintf(t, sizeof t, "%ld", v);
    if (n < 0) {
        b->ok = 0;
        return;
    }
    sb_add(b, t, (size_t)n);
}

/* Exactly the encoding `access` uses: raw IEEE-754 bits, never a formatted
 * float, so libc's float formatter stays off the compared contract. Here it
 * also carries the sign of -0.0 and distinguishes NaN payloads, both of which
 * the printed form collapses. */
static void sb_double(struct sbuf *b, double d) {
    char t[32];
    uint64_t bits;
    int n;
    memcpy(&bits, &d, sizeof bits);
    n = snprintf(t, sizeof t, "%016llx", (unsigned long long)bits);
    if (n < 0) {
        b->ok = 0;
        return;
    }
    sb_add(b, t, (size_t)n);
}

/* Length-prefixed, because a plain delimiter is ambiguous: ["a,b"] and
 * ["a","b"] would render identically and a real divergence between them would
 * be invisible. */
static void sb_bytes(struct sbuf *b, const char *s) {
    if (s == NULL) {
        sb_str(b, "-");
        return;
    }
    sb_int(b, (long)strlen(s));
    sb_str(b, ":");
    sb_str(b, s);
}

/* A number array: `-` for NULL, else the size and every element's valueint and
 * valuedouble. valueint is the point: cJSON_CreateNumber SATURATES the double
 * into an int (cJSON.c:2460), and that saturation is the only interesting
 * computation the typed-array constructors perform. */
static void sb_num_array(struct sbuf *b, cJSON *arr) {
    cJSON *it;
    if (arr == NULL) {
        sb_str(b, "-");
        return;
    }
    sb_int(b, cJSON_GetArraySize(arr));
    for (it = arr->child; it != NULL; it = it->next) {
        sb_str(b, "|");
        sb_int(b, it->valueint);
        sb_str(b, ",");
        sb_double(b, it->valuedouble);
    }
}

static void sb_str_array(struct sbuf *b, cJSON *arr) {
    cJSON *it;
    if (arr == NULL) {
        sb_str(b, "-");
        return;
    }
    sb_int(b, cJSON_GetArraySize(arr));
    for (it = arr->child; it != NULL; it = it->next) {
        sb_str(b, "|");
        sb_bytes(b, it->valuestring);
    }
}

/* The C's own guard, kept at the driver boundary: a negative count or a NULL
 * pointer answers NULL. `avail` is how many whole elements the payload actually
 * holds, and a caller-supplied count is never allowed past it -- passing
 * count > avail is precisely the out-of-bounds read these four constructors
 * cannot detect, so exercising it would make the ORACLE undefined and the
 * comparison meaningless. See cjson_modes.h. */
static int construct_count(long count, size_t avail) {
    if (count < 0) {
        return -1;
    }
    if ((size_t)count > avail) {
        return (int)avail;
    }
    return (int)count;
}

char *cjson_modes_construct(long count, const char *name, const char *raw,
                            const unsigned char *payload, size_t payload_len) {
    /* Capped so the descriptor stays bounded whatever the fuzzer sends. The cap
     * costs no coverage: the count/pointer MISMATCH that the C API cannot
     * detect is untestable at any cap (it is UB in the oracle), and the
     * saturation logic is per element, not per length. */
    enum { MAX_ELEMS = 16 };
    int ivals[MAX_ELEMS];
    float gvals[MAX_ELEMS];
    double dvals[MAX_ELEMS];
    const char *svals[MAX_ELEMS];
    size_t n_i = 0, n_g = 0, n_d = 0, n_s = 0;
    char *scopy = NULL;
    size_t k;

    /* The three number arrays read DISJOINT thirds of the payload: ints first,
     * doubles second, floats third. The string array reads the whole thing.
     *
     * They used to share one buffer, and that made whole classes of case
     * unprobeable. An f64 infinity is 7F F0 00 .. 00, whose high four bytes read
     * as an f32 with an all-ones exponent -- a NaN. An int pair INT_MIN,INT_MAX
     * reads as the f64 0x7FFFFFFF80000000 -- also a NaN. So every interesting
     * value forced a NaN into a SIBLING array, and NaN is the one value this
     * mode cannot put in a probe (it is the ledgered divergence, and a probe
     * asserts the port MATCHES the C). One region per interpretation that can
     * produce a NaN, plus one for the ints; strings need no region of their own
     * because no byte string is a NaN.
     *
     * This is a harness fix, not a cJSON property: several arrays reading one
     * buffer at several widths is a coupling the test invented. */
    size_t third = payload_len / 3;
    const unsigned char *i_reg = payload, *d_reg = payload + third,
                        *g_reg = payload + third * 2;
    size_t i_len = third, d_len = third, g_len = payload_len - third * 2;

    if (i_len > 0) {
        n_i = i_len / sizeof(int);
        if (n_i > MAX_ELEMS) n_i = MAX_ELEMS;
        for (k = 0; k < n_i; k++) memcpy(&ivals[k], i_reg + k * sizeof(int), sizeof(int));
    }
    if (d_len > 0) {
        n_d = d_len / sizeof(double);
        if (n_d > MAX_ELEMS) n_d = MAX_ELEMS;
        for (k = 0; k < n_d; k++) memcpy(&dvals[k], d_reg + k * sizeof(double), sizeof(double));
    }
    if (g_len > 0) {
        n_g = g_len / sizeof(float);
        if (n_g > MAX_ELEMS) n_g = MAX_ELEMS;
        for (k = 0; k < n_g; k++) memcpy(&gvals[k], g_reg + k * sizeof(float), sizeof(float));
    }
    if (payload_len > 0) {
        /* The string elements are the payload split on NUL -- the WHOLE payload,
         * since a string array cannot collide with anything. A private copy,
         * NUL-terminated, so the last field is a valid C string too. */
        scopy = (char *)malloc(payload_len + 1);
        if (scopy == NULL) return NULL;
        memcpy(scopy, payload, payload_len);
        scopy[payload_len] = '\0';
        svals[n_s++] = scopy;
        for (k = 0; k < payload_len && n_s < MAX_ELEMS; k++) {
            if (scopy[k] == '\0') svals[n_s++] = scopy + k + 1;
        }
    }

    /* Each array's pointer is NULL iff its OWN source region is empty, so the
     * `numbers == NULL` guard is reachable per array rather than all-or-nothing
     * (a 1-byte payload gives the int/double arrays NULL and the float array a
     * non-NULL pointer with zero whole elements -- both branches, one input). */
    const int *ip = (i_len > 0) ? ivals : NULL;
    const double *dp = (d_len > 0) ? dvals : NULL;
    const float *gp = (g_len > 0) ? gvals : NULL;
    const char *const *sp = (payload_len > 0) ? svals : NULL;

    cJSON *arr_i = cJSON_CreateIntArray(ip, construct_count(count, n_i));
    cJSON *arr_g = cJSON_CreateFloatArray(gp, construct_count(count, n_g));
    cJSON *arr_d = cJSON_CreateDoubleArray(dp, construct_count(count, n_d));
    cJSON *arr_s = cJSON_CreateStringArray(sp, construct_count(count, n_s));

    cJSON *fal = cJSON_CreateFalse();
    cJSON *boo = cJSON_CreateBool(count != 0);
    cJSON *rw = cJSON_CreateRaw(raw);

    /* All five Add*ToObject calls use the SAME key on purpose: cJSON does not
     * replace a duplicate key, it APPENDS (probed at the builder module), so
     * one input exercises both the add and the duplicate-key path. */
    cJSON *root = cJSON_CreateObject();
    int ok_t = cJSON_AddTrueToObject(root, name) != NULL;
    int ok_f = cJSON_AddFalseToObject(root, name) != NULL;
    int ok_r = cJSON_AddRawToObject(root, name, raw) != NULL;
    int ok_o = cJSON_AddObjectToObject(root, name) != NULL;
    int ok_a = cJSON_AddArrayToObject(root, name) != NULL;
    char *printed = (root != NULL) ? cJSON_PrintUnformatted(root) : NULL;

    size_t cap = 4096 + payload_len * 4 + strlen(name) * 8 + strlen(raw) * 4
               + (printed ? strlen(printed) : 0);
    struct sbuf b;
    b.p = (char *)malloc(cap);
    b.cap = cap;
    b.len = 0;
    b.ok = (b.p != NULL);
    if (b.p != NULL) b.p[0] = '\0';

    sb_str(&b, "false=");
    sb_int(&b, fal ? fal->type : -1);
    sb_str(&b, ";bool=");
    sb_int(&b, boo ? boo->type : -1);
    sb_str(&b, ";raw=");
    sb_bytes(&b, rw ? rw->valuestring : NULL);
    sb_str(&b, ";ints=");
    sb_num_array(&b, arr_i);
    sb_str(&b, ";flts=");
    sb_num_array(&b, arr_g);
    sb_str(&b, ";dbls=");
    sb_num_array(&b, arr_d);
    sb_str(&b, ";strs=");
    sb_str_array(&b, arr_s);
    sb_str(&b, ";addT=");
    sb_int(&b, ok_t);
    sb_str(&b, ";addF=");
    sb_int(&b, ok_f);
    sb_str(&b, ";addR=");
    sb_int(&b, ok_r);
    sb_str(&b, ";addO=");
    sb_int(&b, ok_o);
    sb_str(&b, ";addA=");
    sb_int(&b, ok_a);
    sb_str(&b, ";obj=");
    sb_str(&b, printed ? printed : "-");

    cJSON_free(printed);
    cJSON_Delete(root);
    cJSON_Delete(rw);
    cJSON_Delete(boo);
    cJSON_Delete(fal);
    cJSON_Delete(arr_s);
    cJSON_Delete(arr_d);
    cJSON_Delete(arr_g);
    cJSON_Delete(arr_i);
    free(scopy);

    if (!b.ok) {
        free(b.p);
        return NULL;
    }
    return b.p;
}

/* ---- `set` mode: the two in-place setters -------------------------------- */

/* One item, as the struct fields a C caller reads straight off the pointer plus
 * its printed form. `valuedouble` is here because it is the field
 * cJSON_SetNumberHelper writes, and it writes it WITHOUT a type check — so a
 * string node can end up carrying a number, which no accessor would ever show.
 * The descriptor shows it, which is the whole point: an intentional divergence
 * has to be observable or the ledger entry is asserting something unmeasured
 * (LESSONS #31). */
static void sb_item(struct sbuf *b, const cJSON *it) {
    char *printed;
    if (it == NULL) {
        sb_str(b, "-");
        return;
    }
    sb_str(b, "t");
    sb_int(b, it->type);
    sb_str(b, ",i");
    sb_int(b, it->valueint);
    sb_str(b, ",d");
    sb_double(b, it->valuedouble);
    sb_str(b, ",s");
    sb_bytes(b, it->valuestring);
    sb_str(b, ",p");
    printed = cJSON_PrintUnformatted(it);
    sb_str(b, printed ? printed : "-");
    cJSON_free(printed);
}

char *cjson_modes_set(double num, const char *key, const char *newstr,
                      const char *json, size_t json_len) {
    /* A NULL root is NOT an error here (unlike `access`/`query`): the setters
     * are the surface under test and they must still run, so an unparseable
     * document just means the document-target calls take their NULL path. */
    cJSON *root = cJSON_ParseWithLength(json, json_len);
    cJSON *target = (root != NULL)
                        ? cJSON_GetObjectItemCaseSensitive(root, key)
                        : NULL;

    /* Called with `target` even when it is NULL: cJSON_SetValuestring's FIRST
     * guard is `object == NULL`, so passing NULL is how that branch is
     * exercised rather than assumed. cJSON_SetNumberHelper below has no such
     * guard, which is why it is the one call that must be conditional. */
    const char *sv = cJSON_SetValuestring(target, newstr);
    int have_sn = (target != NULL);
    double sn = have_sn ? cJSON_SetNumberHelper(target, num) : 0.0;

    /* A fresh string node whose OLD value is the key: with key and newstr both
     * caller-controlled, one input reaches either side of
     * `strlen(new) <= strlen(old)` (cJSON.c:416). The two paths are not
     * distinguishable from outside — the shorter one reuses the buffer and the
     * longer one allocates, but both leave `valuestring` equal to the new C
     * string and both return it — so this crosses the branch without being
     * able to tell which side it took. Said out loud because assuming a branch
     * is covered because an input reaches it is how the C's own defects
     * survive. */
    cJSON *s2 = cJSON_CreateString(key);
    const char *sv2 = cJSON_SetValuestring(s2, newstr);
    /* the documented NULL-replacement error path (cJSON.c:402 comment) */
    const char *svnull = cJSON_SetValuestring(s2, NULL);

    /* A NUMBER node: first the "not a cJSON_String" guard, then the setter that
     * owns this node's type. Same node for both so the descriptor shows the
     * number setter's effect on a node the string setter just refused. */
    cJSON *n2 = cJSON_CreateNumber(0);
    const char *svnum = cJSON_SetValuestring(n2, newstr);
    double sn2 = (n2 != NULL) ? cJSON_SetNumberHelper(n2, num) : 0.0;

    char *proot = (root != NULL) ? cJSON_PrintUnformatted(root) : NULL;

    size_t cap = 4096 + (strlen(key) + strlen(newstr) + json_len
                         + (proot ? strlen(proot) : 0)) * 8;
    struct sbuf b;
    b.p = (char *)malloc(cap);
    b.cap = cap;
    b.len = 0;
    b.ok = (b.p != NULL);
    if (b.p != NULL) b.p[0] = '\0';

    sb_str(&b, "tgt=");
    sb_item(&b, target);
    sb_str(&b, ";sv=");
    sb_bytes(&b, sv);
    sb_str(&b, ";sn=");
    if (have_sn) sb_double(&b, sn); else sb_str(&b, "-");
    sb_str(&b, ";s2=");
    sb_item(&b, s2);
    sb_str(&b, ";sv2=");
    sb_bytes(&b, sv2);
    sb_str(&b, ";svnull=");
    sb_bytes(&b, svnull);
    sb_str(&b, ";svnum=");
    sb_bytes(&b, svnum);
    sb_str(&b, ";n2=");
    sb_item(&b, n2);
    sb_str(&b, ";sn2=");
    sb_double(&b, sn2);
    sb_str(&b, ";doc=");
    sb_str(&b, proot ? proot : "-");

    cJSON_free(proot);
    cJSON_Delete(n2);
    cJSON_Delete(s2);
    cJSON_Delete(root);

    if (!b.ok) {
        free(b.p);
        return NULL;
    }
    return b.p;
}

/* ---- `seq` mode: the removal + placement surfaces, driven as a program ---- */

/* The driver's index rule, identical to `access`'s: strtol base 10 with the
 * result clamped into int, so junk reads as 0 and an overflowing literal
 * saturates instead of wrapping. Both sides must agree on this before
 * cJSON_DetachItemFromArray ever sees an int. */
static int seq_index(const char *s) {
    long v = strtol(s, NULL, 10);
    if (v > INT_MAX) v = INT_MAX;
    if (v < INT_MIN) v = INT_MIN;
    return (int)v;
}

/* One step's record. `r` is the op's own answer (`-` where the C returns void),
 * `got`/`key` the detached node and the key it still carries, `sz` the target's
 * child count AFTER the op, and `doc` the whole document. `doc` is what makes a
 * later-surfacing corruption visible (LESSONS #39 -- after EVERY step, because
 * a bug that corrupts state at step 2 and is masked at step 5 is invisible to a
 * final-state comparison); `sz` is what makes it visible even when
 * the printer hides it (the printer ignores a child hung off a scalar, but
 * cJSON_GetArraySize does not). */
static void sb_step(struct sbuf *b, const char *name, int r,
                    cJSON *got, cJSON *target, cJSON *root) {
    char *pgot = (got != NULL) ? cJSON_PrintUnformatted(got) : NULL;
    char *pdoc = (root != NULL) ? cJSON_PrintUnformatted(root) : NULL;
    sb_str(b, "|");
    sb_str(b, name);
    sb_str(b, ":r=");
    if (r < 0) sb_str(b, "-"); else sb_int(b, r);
    sb_str(b, ",got=");
    sb_str(b, pgot ? pgot : "-");
    sb_str(b, ",key=");
    sb_bytes(b, (got != NULL) ? got->string : NULL);
    sb_str(b, ",sz=");
    sb_int(b, (target != NULL) ? cJSON_GetArraySize(target) : -1);
    sb_str(b, ",doc=");
    sb_str(b, pdoc ? pdoc : "-");
    cJSON_free(pgot);
    cJSON_free(pdoc);
}

char *cjson_modes_seq(const char *json, size_t json_len,
                      const char *ops, size_t ops_len) {
    cJSON *root = cJSON_ParseWithLength(json, json_len);
    if (root == NULL) return NULL;

    /* A private, NUL-terminated copy: the fields are split in place with NULs so
     * every one reaches cJSON as a C string, and the caller's buffer is left
     * alone. */
    char *buf = (char *)malloc(ops_len + 1);
    if (buf == NULL) { cJSON_Delete(root); return NULL; }
    memcpy(buf, ops, ops_len);
    buf[ops_len] = '\0';

    char *proot = cJSON_PrintUnformatted(root);
    size_t p = (proot != NULL) ? strlen(proot) : 0;
    /* Every step prints at most the document, the detached node and its key.
     * Only `app` and `ins` GROW the document, by one number each -- at most 11
     * digits per step, so CJSON_SEQ_MAX_OPS steps add far less than the 256
     * bytes of slack carried per step below. */
    size_t cap = 4096 + (size_t)(CJSON_SEQ_MAX_OPS + 1) * (3 * (p + 256) + 192);
    struct sbuf b;
    b.p = (char *)malloc(cap);
    b.cap = cap;
    b.len = 0;
    b.ok = (b.p != NULL);
    if (b.p != NULL) b.p[0] = '\0';

    sb_str(&b, "init=");
    sb_str(&b, proot ? proot : "-");
    cJSON_free(proot);

    char *line = buf;
    for (int n = 0; n < CJSON_SEQ_MAX_OPS && line != NULL && *line != '\0'; n++) {
        char *nl = strchr(line, '\n');
        if (nl != NULL) *nl = '\0';
        char *next = (nl != NULL) ? nl + 1 : NULL;

        /* <opcode>\t<selector>\t<arg>; a missing field reads as empty */
        char *sel = strchr(line, '\t');
        char *arg = NULL;
        if (sel != NULL) {
            *sel++ = '\0';
            arg = strchr(sel, '\t');
            if (arg != NULL) *arg++ = '\0';
        }
        if (sel == NULL) sel = (char *)"";
        if (arg == NULL) arg = (char *)"";

        /* Empty selector = the root; otherwise a case-sensitive key of it. One
         * level, on purpose -- see cjson_modes.h. */
        cJSON *target = (*sel == '\0')
                            ? root
                            : cJSON_GetObjectItemCaseSensitive(root, sel);

        cJSON *got = NULL;
        int r = -1;
        const char *name = "?";
        if (strcmp(line, "da") == 0) {
            name = "da";
            got = cJSON_DetachItemFromArray(target, seq_index(arg));
            r = (got != NULL);
        } else if (strcmp(line, "xa") == 0) {
            name = "xa";
            cJSON_DeleteItemFromArray(target, seq_index(arg));
        } else if (strcmp(line, "do") == 0) {
            name = "do";
            got = cJSON_DetachItemFromObject(target, arg);
            r = (got != NULL);
        } else if (strcmp(line, "dos") == 0) {
            name = "dos";
            got = cJSON_DetachItemFromObjectCaseSensitive(target, arg);
            r = (got != NULL);
        } else if (strcmp(line, "xo") == 0) {
            name = "xo";
            cJSON_DeleteItemFromObject(target, arg);
        } else if (strcmp(line, "xos") == 0) {
            name = "xos";
            cJSON_DeleteItemFromObjectCaseSensitive(target, arg);
        } else if (strcmp(line, "app") == 0) {
            name = "app";
            /* ARRAY targets only -- the C would accept any parent, and the two
             * malformed trees that produces (a child hung off a scalar, an
             * object member with a NULL key) are the `scalar-parent-child`
             * class this module deliberately does not own. */
            if (cJSON_IsArray(target)) {
                r = cJSON_AddItemToArray(target, cJSON_CreateNumber(seq_index(arg))) ? 1 : 0;
            } else {
                r = 0;
            }
        } else if (strcmp(line, "ins") == 0) {
            name = "ins";
            /* ARRAY only, same reason as `app`. Note what this op does NOT
             * fail at: an index past the end is not an error -- the C falls
             * through to add_item_to_array and appends (probed, see
             * spikes/place_relink.c), so `ins 99` on a 2-element array
             * succeeds and grows it to 3. */
            r = 0;
            if (cJSON_IsArray(target)) {
                cJSON *item = cJSON_CreateNumber(seq_index(arg));
                r = cJSON_InsertItemInArray(target, seq_index(arg), item) ? 1 : 0;
                /* Ownership transfers only on SUCCESS; on every failure path
                 * the caller still owns the node. Omitting this leaks, which is
                 * how it was found -- LeakSanitizer named the `which < 0` case
                 * in this mode's own probe program. The gate that would now
                 * catch the same slip HERE, rather than in a throwaway probe,
                 * is check.sh step 4a (LESSONS #40): this file is the C the
                 * port wrote, and a leak in it changes no stdout. */
                if (!r) cJSON_Delete(item);
            }
        } else if (strcmp(line, "rep") == 0) {
            name = "rep";
            r = 0;
            if (cJSON_IsArray(target)) {
                cJSON *item = cJSON_CreateNumber(seq_index(arg));
                r = cJSON_ReplaceItemInArray(target, seq_index(arg), item) ? 1 : 0;
                if (!r) cJSON_Delete(item);
            }
        } else if (strcmp(line, "ro") == 0 || strcmp(line, "ros") == 0) {
            /* NOT restricted to a container: every way these fail -- missing
             * key, non-object parent, empty container -- is representable on
             * both sides, so the guards themselves are worth comparing.
             *
             * The value is the key's length purely so successive replaces are
             * distinguishable in the descriptor; the interesting part is the
             * position and the KEY, which the C rewrites to the lookup string
             * (a case-insensitive replace of `a` in {"A":1} leaves {"a":...}). */
            int cs = (line[2] == 's');
            name = cs ? "ros" : "ro";
            cJSON *item = cJSON_CreateNumber((double)strlen(arg));
            r = (cs ? cJSON_ReplaceItemInObjectCaseSensitive(target, arg, item)
                    : cJSON_ReplaceItemInObject(target, arg, item)) ? 1 : 0;
            if (!r) cJSON_Delete(item);
        }

        sb_step(&b, name, r, got, target, root);
        /* the detach entry points transfer OWNERSHIP to the caller */
        cJSON_Delete(got);
        line = next;
    }

    free(buf);
    cJSON_Delete(root);
    if (!b.ok) {
        free(b.p);
        return NULL;
    }
    return b.p;
}

char *cjson_modes_query(const char *key, const char *json, size_t json_len) {
    cJSON *item = cJSON_ParseWithLength(json, json_len);
    if (item == NULL) return NULL;
    cJSON *got = cJSON_GetObjectItemCaseSensitive(item, key);
    if (got == NULL) {
        cJSON_Delete(item);
        return strdup("missing");
    }
    char *printed = cJSON_PrintUnformatted(got);
    if (printed == NULL) { cJSON_Delete(item); return NULL; }

    size_t cap = strlen(printed) + 256
               + (got->valuestring ? strlen(got->valuestring) : 1);
    char *out = (char *)malloc(cap);
    if (out == NULL) { cJSON_free(printed); cJSON_Delete(item); return NULL; }
    out[0] = '\0';
    strncat(out, "is=", cap - 1);
    append_flags(out, cap, got);
    /* the struct fields a C caller reads straight off the pointer */
    size_t n = strlen(out);
    snprintf(out + n, cap - n, ";type=%d;int=%d;str=%s;size=%d;print=%s",
             got->type, got->valueint,
             got->valuestring ? got->valuestring : "-",
             cJSON_GetArraySize(got), printed);
    cJSON_free(printed);
    cJSON_Delete(item);
    return out;
}

/* ---- `opts` mode: the four options entry points ---- */

/* Raw bytes as `<n>:<hex>`. The preallocated buffer is memset to 0 before the
 * call and the C writes a NUL-terminated PREFIX into it on failure, so interior
 * NULs are the whole point and sb_bytes' C-string form would hide exactly the
 * divergence this field exists to measure. */
static void sb_hex(struct sbuf *b, const unsigned char *p, size_t n) {
    static const char HEX[] = "0123456789abcdef";
    size_t i;
    if (p == NULL) {
        sb_str(b, "-");
        return;
    }
    sb_int(b, (long)n);
    sb_str(b, ":");
    for (i = 0; i < n; i++) {
        char t[2];
        t[0] = HEX[(p[i] >> 4) & 0xF];
        t[1] = HEX[p[i] & 0xF];
        sb_add(b, t, 2);
    }
}

/* cJSON_PrintPreallocated over a buffer allocated to EXACTLY `len`, zeroed
 * first. `out` (when non-NULL) receives the buffer's bytes afterwards. A
 * negative `len` never reaches cJSON: the port cannot spell it, so both sides
 * answer false here instead (see the header). */
static int ppa_once(cJSON *doc, int len, int fmt, unsigned char *out) {
    char *buf;
    int r;
    if (doc == NULL || len < 0) return 0;
    buf = (char *)malloc((size_t)len + 1); /* +1: malloc(0) must not be NULL */
    if (buf == NULL) return 0;
    memset(buf, 0, (size_t)len + 1);
    r = cJSON_PrintPreallocated(doc, buf, len, fmt) ? 1 : 0;
    if (out != NULL && len > 0) memcpy(out, buf, (size_t)len);
    free(buf);
    return r;
}

char *cjson_modes_opts(int flags, int prebuffer, int prealloc,
                       const char *json, size_t json_len) {
    int rnt = (flags & 1) ? 1 : 0;
    int fmt = (flags & 2) ? 1 : 0;
    const char *end_l = NULL;
    const char *end_o = NULL;
    cJSON *by_len;
    cJSON *by_str;
    cJSON *doc;
    char *pwl = NULL;
    char *pwo = NULL;
    char *pb = NULL;
    char *ref = NULL;
    unsigned char *ppabuf = NULL;
    int ppa = 0;
    long ppamin = -1;
    size_t cap;
    struct sbuf b;

    if (prebuffer > CJSON_OPTS_MAX_BUF) prebuffer = CJSON_OPTS_MAX_BUF;
    if (prealloc > CJSON_OPTS_MAX_BUF) prealloc = CJSON_OPTS_MAX_BUF;

    /* The length form first: it sees the exact byte count, so an embedded NUL
     * or a missing terminator is visible to it and not to the string form. */
    by_len = cJSON_ParseWithLengthOpts(json, json_len, &end_l, rnt);
    by_str = cJSON_ParseWithOpts(json, &end_o, rnt);
    doc = (by_len != NULL) ? by_len : by_str;

    if (by_len != NULL) pwl = cJSON_PrintUnformatted(by_len);
    if (by_str != NULL) pwo = cJSON_PrintUnformatted(by_str);
    if (doc != NULL) pb = cJSON_PrintBuffered(doc, prebuffer, fmt);
    if (doc != NULL) ref = fmt ? cJSON_Print(doc) : cJSON_PrintUnformatted(doc);

    /* The predicate, not a sample of it: scan for the smallest length that
     * succeeds. Bounded by the reference print's length, which is what the
     * accounting is a function of. */
    if (ref != NULL) {
        int len;
        int limit = (int)strlen(ref) + 4;
        if (limit > CJSON_OPTS_MAX_BUF) limit = CJSON_OPTS_MAX_BUF;
        for (len = 0; len <= limit; len++) {
            if (ppa_once(doc, len, fmt, NULL)) {
                ppamin = len;
                break;
            }
        }
    }

    if (prealloc > 0) {
        ppabuf = (unsigned char *)malloc((size_t)prealloc);
        if (ppabuf != NULL) memset(ppabuf, 0, (size_t)prealloc);
    }
    ppa = ppa_once(doc, prealloc, fmt, ppabuf);

    cap = 4096 + json_len * 4
        + (pwl ? strlen(pwl) : 0) * 2 + (pwo ? strlen(pwo) : 0) * 2
        + (pb ? strlen(pb) : 0) * 2 + (size_t)(prealloc > 0 ? prealloc : 0) * 2;
    b.p = (char *)malloc(cap);
    b.cap = cap;
    b.len = 0;
    b.ok = (b.p != NULL);
    if (b.p != NULL) b.p[0] = '\0';

    sb_str(&b, "pwl=");
    sb_bytes(&b, pwl);
    sb_str(&b, ";pwlend=");
    sb_int(&b, end_l ? (long)(end_l - json) : -1);
    sb_str(&b, ";pwo=");
    sb_bytes(&b, pwo);
    sb_str(&b, ";pwoend=");
    sb_int(&b, end_o ? (long)(end_o - json) : -1);
    sb_str(&b, ";pb=");
    sb_bytes(&b, pb);
    sb_str(&b, ";ppamin=");
    sb_int(&b, ppamin);
    sb_str(&b, ";ppa=");
    sb_int(&b, ppa);
    sb_str(&b, ";ppabuf=");
    sb_hex(&b, ppabuf, (size_t)(prealloc > 0 ? prealloc : 0));

    free(ppabuf);
    cJSON_free(ref);
    cJSON_free(pb);
    cJSON_free(pwo);
    cJSON_free(pwl);
    cJSON_Delete(by_str);
    cJSON_Delete(by_len);

    if (!b.ok) {
        free(b.p);
        return NULL;
    }
    return b.p;
}

/* ---- `parent` mode: the non-container parent ---- */

/* Build the target node named by `kind`. `doc` hands back the parsed document
 * root (NULL when it did not parse), which is how a fuzzer chooses the type;
 * every other kind is a fresh node this function owns. `*owned` says which,
 * because the document root is freed by the caller's cJSON_Delete(root) and
 * must not be freed twice. */
static cJSON *parent_target(const char *kind, cJSON *root, int *owned) {
    *owned = 1;
    if (strcmp(kind, "num") == 0)   return cJSON_CreateNumber(7);
    if (strcmp(kind, "str") == 0)   return cJSON_CreateString("s");
    if (strcmp(kind, "true") == 0)  return cJSON_CreateTrue();
    if (strcmp(kind, "false") == 0) return cJSON_CreateFalse();
    if (strcmp(kind, "null") == 0)  return cJSON_CreateNull();
    if (strcmp(kind, "raw") == 0)   return cJSON_CreateRaw("RAW");
    if (strcmp(kind, "arr") == 0)   return cJSON_CreateArray();
    if (strcmp(kind, "obj") == 0)   return cJSON_CreateObject();
    /* "doc", and anything unrecognised, is the document root */
    *owned = 0;
    return root;
}

/* One lookup pair: the case-INsensitive entry point, then the case-SENSITIVE
 * one. They are reported separately because a NULL-keyed member makes them
 * disagree -- that disagreement is the finding (see cjson_modes.h). */
static void sb_lookup(struct sbuf *b, cJSON *target, const char *name) {
    sb_str(b, cJSON_GetObjectItem(target, name) ? "1" : "0");
    sb_str(b, "/");
    sb_str(b, cJSON_GetObjectItemCaseSensitive(target, name) ? "1" : "0");
}

char *cjson_modes_parent(const char *kind, const char *op, const char *key,
                         const char *json, size_t json_len) {
    cJSON *root = cJSON_ParseWithLength(json, json_len);
    int owned = 0;
    cJSON *target = parent_target(kind, root, &owned);
    int r = 0;

    /* `pre` goes in only when the target is ALREADY an object: adding a keyed
     * member to a number would itself be the malformed operation and would
     * confuse the experiment with its own setup. Same rule on both sides. */
    if (target != NULL && cJSON_IsObject(target)) {
        cJSON_AddNumberToObject(target, "pre", 1);
    }

    if (target != NULL) {
        if (strcmp(op, "a") == 0) {
            cJSON *item = cJSON_CreateNumber(99);
            r = cJSON_AddItemToArray(target, item) ? 1 : 0;
            if (!r) cJSON_Delete(item);          /* refused -> still ours */
        } else if (strcmp(op, "o") == 0) {
            cJSON *item = cJSON_CreateNumber(99);
            r = cJSON_AddItemToObject(target, key, item) ? 1 : 0;
            if (!r) cJSON_Delete(item);
        } else if (strcmp(op, "ocs") == 0) {
            /* CS = the key is NOT copied; the node borrows this pointer, so it
             * must outlive the node. `key` points into the driver's stdin
             * buffer, which does -- it is freed after this function returns. */
            cJSON *item = cJSON_CreateNumber(99);
            r = cJSON_AddItemToObjectCS(target, key, item) ? 1 : 0;
            if (!r) cJSON_Delete(item);
        } else if (strcmp(op, "t") == 0) {
            r = cJSON_AddTrueToObject(target, key) ? 1 : 0;
        } else if (strcmp(op, "f") == 0) {
            r = cJSON_AddFalseToObject(target, key) ? 1 : 0;
        } else if (strcmp(op, "z") == 0) {
            r = cJSON_AddNullToObject(target, key) ? 1 : 0;
        } else if (strcmp(op, "m") == 0) {
            r = cJSON_AddNumberToObject(target, key, 5) ? 1 : 0;
        } else if (strcmp(op, "s") == 0) {
            r = cJSON_AddStringToObject(target, key, "v") ? 1 : 0;
        } else {
            r = -1;                              /* unknown op */
        }
    } else {
        r = -1;
    }

    /* `post` is the load-bearing member: an ORDINARY keyed member added AFTER
     * whatever the op did. If the op left a NULL-keyed member behind, the
     * case-SENSITIVE lookup can no longer reach `post` while the
     * case-INsensitive one still can. */
    if (target != NULL && cJSON_IsObject(target)) {
        cJSON_AddNumberToObject(target, "post", 2);
    }

    char *ptarget = (target != NULL) ? cJSON_PrintUnformatted(target) : NULL;
    cJSON *item0 = (target != NULL) ? cJSON_GetArrayItem(target, 0) : NULL;
    char *pitem0 = (item0 != NULL) ? cJSON_PrintUnformatted(item0) : NULL;

    /* Duplicate and Compare are carried to PIN their blindness, not because a
     * divergence is expected in them: the spike showed Compare calls a
     * malformed node equal to a clean one and Duplicate copies the hung child.
     * A ledger that omitted them would imply the divergence is wider. */
    cJSON *dup = (target != NULL) ? cJSON_Duplicate(target, 1) : NULL;
    int cmp = (target != NULL && dup != NULL && cJSON_Compare(target, dup, 1)) ? 1 : 0;

    size_t cap = 4096 + json_len * 2 + strlen(key) * 4
               + (ptarget ? strlen(ptarget) : 0) * 2;
    struct sbuf b;
    b.p = (char *)malloc(cap);
    b.cap = cap;
    b.len = 0;
    b.ok = (b.p != NULL);
    if (b.p != NULL) b.p[0] = '\0';

    sb_str(&b, "rc=");
    sb_int(&b, r);
    sb_str(&b, ";print=");
    sb_bytes(&b, ptarget);
    sb_str(&b, ";size=");
    sb_int(&b, (target != NULL) ? cJSON_GetArraySize(target) : -1);
    sb_str(&b, ";item0=");
    sb_str(&b, pitem0 ? pitem0 : "-");
    /* each lookup as <case-insensitive>/<case-sensitive> */
    sb_str(&b, ";pre=");
    sb_lookup(&b, target, "pre");
    sb_str(&b, ";post=");
    sb_lookup(&b, target, "post");
    sb_str(&b, ";key=");
    sb_lookup(&b, target, key);
    sb_str(&b, ";empty=");
    sb_lookup(&b, target, "");
    sb_str(&b, ";dupsz=");
    sb_int(&b, (dup != NULL) ? cJSON_GetArraySize(dup) : -1);
    sb_str(&b, ";cmp=");
    sb_int(&b, cmp);
    sb_str(&b, ";doc=");
    if (root != NULL) {
        char *proot = cJSON_PrintUnformatted(root);
        sb_str(&b, proot ? proot : "-");
        cJSON_free(proot);
    } else {
        sb_str(&b, "-");
    }

    cJSON_Delete(dup);
    cJSON_free(pitem0);
    cJSON_free(ptarget);
    if (owned) cJSON_Delete(target);
    cJSON_Delete(root);

    if (!b.ok) {
        free(b.p);
        return NULL;
    }
    return b.p;
}
