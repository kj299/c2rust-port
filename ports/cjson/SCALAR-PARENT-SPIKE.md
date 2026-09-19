# Spike — the non-container parent (`scalar-parent-child`), before scheduling it

**Status: design spike, not a port.** The port's *behaviour* here has been
correct since module 6. What is missing is evidence: no driver mode has ever
built a non-container parent, so nothing observes the difference. This spike
establishes what the C actually does, so the divergence can be measured rather
than asserted.

Written because three modules have now routed around this one class and each
said so in writing (`DIVERGENCES.md` · `scalar-parent-child`). The repetition is
the argument for scheduling it rather than restating the refusal a fourth time.

Scope: `cJSON_AddItemToArray`, `cJSON_AddItemToObject`, `cJSON_AddItemToObjectCS`
and the `cJSON_Add*ToObject` helpers that delegate to them — specifically their
behaviour when the parent is **not** the container the name implies.

## The hazard log

**Every row carries its Evidence.** `ran:` means a committed program under
`spikes/` produced the quoted result on this machine (LESSONS #38).

| # | Hazard | Evidence | What the port does |
|---|---|---|---|
| H1 | A child hangs off **any** scalar — number, string, true, false, null, raw. Print ignores it; `GetArraySize`/`GetArrayItem` do not. | `ran: spikes/scalar_parent.c` | `Value::Number` has nowhere to put a child. `add_item_to_array` answers **false**. |
| H2 | `AddItemToArray` on an **object** makes a member with a **NULL key**, which prints as `""` but is not the same node as a member keyed `""`. | `ran: spikes/scalar_parent.c` | A `Value::Object` entry always has a key; "present but unfindable" is unrepresentable. Answers **false**. |
| H2b | **That NULL key blinds `GetObjectItemCaseSensitive` to every member after it.** The case-sensitive loop stops at a NULL `string`; the case-insensitive one walks past. | `ran: spikes/scalar_parent.c` | Unreachable — the port never builds the state. |
| H3 | `AddItemToObject` on an **array** stores a key the array printer never emits, so a print round-trip silently loses it. | `ran: spikes/scalar_parent.c` | Answers **false**. |
| H4 | `Duplicate` faithfully **copies** the hung child, propagating the malformed tree. | `ran: spikes/scalar_parent.c` | Nothing to copy. |
| H5 | **`Compare` says a malformed node EQUALS a clean one.** It never looks at a non-container's children. | `ran: spikes/scalar_parent.c` | Nothing to compare. |
| H6 | The only guards are NULL item, NULL parent, self-reference, and (for the object form) NULL key. No type check anywhere. | `ran: spikes/scalar_parent.c` | Same guards, plus the type check the C lacks. |
| H7 | `AddItemToObjectCS` onto a scalar then `Delete` — the const-key path frees correctly; no leak, no bad free. | `ran: spikes/scalar_parent.c` | N/A. |
| H8 | Nested: a malformed scalar inside a real array is invisible to the array's print but still reports `GetArraySize` 1. | `ran: spikes/scalar_parent.c` | N/A. |

No `read` rows. Everything above was executed under ASan + UBSan + LSan;
`spikes/run.sh` re-derives it.

## What the run actually printed

Clean **exit 0** under ASan+UBSan+LSan. Every finding is behavioural, not a
memory error — which is itself a result: this is a correctness hazard the
sanitizers cannot catch, so only a differential can.

### H1 — a child on every scalar

```
  add->number  rc=1  print=7        size=1  item[0]=99
  add->string  rc=1  print="s"      size=1  item[0]=99
  add->true    rc=1  print=true     size=1  item[0]=99
  add->false   rc=1  print=false    size=1  item[0]=99
  add->null    rc=1  print=null     size=1  item[0]=99
  add->raw     rc=1  print=RAW      size=1  item[0]=99
```

The print column is why this survived fourteen modules undetected: **the
printer is blind to it.** A differential that compares printed bytes reports
MATCH on every one of these. `GetArraySize` and `GetArrayItem` are what make the
state observable, which decides the mode's descriptor below.

### H2 / H2b — the NULL-keyed member, and the lookup it breaks

```
  object with a NULL key       print={"a":1,"":2,"b":3}     size=3
  GetObjectItem("a")              = found   (case-INsensitive)
  GetObjectItem("b")              = found   <- AFTER the NULL key
  GetObjectItemCaseSensitive("a") = found
  GetObjectItemCaseSensitive("b") = NULL   <- AFTER the NULL key
  GetObjectItem("")               = NULL
```

Three separate facts, and the middle one is worse than the ledger's existing
description of this class:

1. **The document prints as `{"a":1,"":2,"b":3}`** — it looks like an ordinary
   object with an empty-string key. Parse that printed text back and you get a
   document where `""` *is* findable. The printed form misrepresents the tree.
2. **`cJSON_GetObjectItemCaseSensitive("b")` returns NULL.** `"b"` is a
   perfectly ordinary member added after the malformed one, and it has become
   unfindable — the case-sensitive loop's condition includes
   `current_element->string != NULL` (cJSON.c:1910), so the walk *stops* at the
   NULL key and never reaches anything behind it. One malformed member is a
   denial-of-lookup for the entire remainder of the object.
3. **The two lookups disagree.** `case_insensitive_strcmp` returns 1 for a NULL
   argument (cJSON.c:135) rather than stopping, so `cJSON_GetObjectItem` walks
   past and still finds `"b"`. Two functions documented to differ only in case
   sensitivity differ in reachability.

And `GetObjectItem("")` is NULL, so the member that *prints* as `""` cannot be
retrieved by the key it appears to have. This is the precise reason the port's
`Value::Object` cannot represent the state: an entry has a key or it does not
exist, and there is no key whose lookup behaviour is "matches nothing, and hides
everything after me".

### H3 — a key inside an array, dropped by print

```
  rc=1
  array carrying a key         print=[1,2]                  size=2
```

`cJSON_AddItemToObject(array, "k", item)` succeeds and stores the key;
`print_array` never emits it. Print round-trip loses it silently — another state
a bytes-comparing differential cannot see.

### H4 / H5 — Duplicate propagates it, Compare cannot see it

```
  original  (number + child)   print=7                      size=1
  duplicate                    print=7                      size=1
  Compare(malformed, clean number 7) = EQUAL
  Compare(malformed, its duplicate)  = EQUAL
```

`cJSON_Duplicate` copies the hung child, so the malformation propagates through
any code that clones. `cJSON_Compare` reports a malformed node **equal** to a
clean one, because it never examines a non-container's children. So of the
port's three existing comparison surfaces — print, Compare, dup — **not one can
observe this class.** That is the finding that decides the module's shape.

### H6 — the guards that do exist

```
  AddItemToArray(arr, NULL)      rc=0  (item NULL)
  AddItemToArray(NULL, item)     rc=0  (parent NULL)
  AddItemToArray(arr, arr)       rc=0  (self-reference)
  AddItemToObject(obj, NULL, it) rc=0  (NULL key)
```

Four guards, none of them a type check. Worth comparing on both sides: the port
has all four *and* the type check, so these rows should MATCH while the
type-check rows diverge — which is what keeps the ledger honest about exactly
where the difference is.

### H7 / H8

`AddItemToObjectCS` onto a scalar then `Delete` is clean (no leak, no bad free —
LSan). A malformed scalar nested inside a real array leaves the array printing
`[7,8]` while `GetArraySize(item[0])` still answers 1.

## The API-shape decision this forces

The C's signature `cJSON_AddItemToArray(cJSON *array, cJSON *item)` encodes an
invariant — *array is an array* — that the function never checks. The port's is
`add_item_to_array(&mut Value, Value) -> bool`, and `Value::Array(Vec<Value>)`
is the only variant with anywhere to put a child, so the invariant is carried by
the type rather than by a comment.

That makes the malformed tree **unrepresentable**, not merely rejected. This is
a Prime Directive refusal: reproducing it faithfully would mean giving every
`Value` variant a child list purely so the port could build documents whose
printed form misrepresents them and whose members hide each other from lookup.
The port answers `false` and that is the safer answer.

## Harness machinery the module will need

**A new driver mode.** None of the existing ones can build the state: `seq`'s
`app`/`ins`/`rep` ops explicitly refuse a non-array target (that refusal is the
thing being lifted), and `construct`/`build` only assemble well-formed trees.

**The descriptor cannot be print-based.** H1, H3, H4 and H5 together establish
that print, `Compare` and `dup` are all blind to this class. The mode must
report the *container view* — `cJSON_GetArraySize`, `cJSON_GetArrayItem(0)` —
and, for the object cases, the **two lookups separately**, because H2b makes
them disagree. A mode that reported only printed bytes would return MATCH on
every case it exists to test (LESSONS #39's shape: compare the state no output
depends on, by naming the operation that consumes it).

**A corrected reference oracle (LESSONS #28).** The divergence is
predicate-defined — *every* non-container parent triggers it, and a fuzzer
choosing targets at random will hit one constantly — so there is no finite
fingerprint set. Differential fuzzing needs a C that shares the port's type
check; `oracle/make_fixed_core.py` gains a fourth correction. Per LESSONS #42
that patch's width must then be measured against the pristine oracle rather than
argued.

**The `seq` mode's array-only restriction should be lifted once this lands** —
on the sides where the port can now answer. That is what makes this increment
worth doing rather than restating: it buys back coverage in three other modes.
