# Spike — the cJSON mutation API, before scheduling it

**Status: design spike, not a port.** No mutation symbol is ported by this
document. Its job is to answer three questions before a module is scheduled:
what are the hazards, how should the work be split, and does it need a
mutation-*sequence* fuzzer rather than the single-shot modes every other module
uses.

> **Progress against §4's split (updated 2026-09-07).** Module 3 of 3,
> **`dom-mutate-set`**, has LANDED: `cJSON_SetValuestring` and
> `cJSON_SetNumberHelper` are on the compared contract via the `set` driver mode,
> and API-COVERAGE.md's ceiling ratcheted 18 → 16. `dom-mutate-remove` and
> `dom-mutate-place` are still queued, so everything below about H1/H2/H3 and the
> sequence mode stands unchanged. The one thing the module CHANGED in this
> document is H6, which was wrong about where the danger in
> `cJSON_SetValuestring` is — see H7.

Written because the kit's most expensive lesson says so — *"spike the scary
module before scheduling it"* (the winlsof hang: 7 reactive commits vs ~1 day up
front, CLAUDE.md "Habits the retrospective bought in blood").

Scope: the 14 symbols API-COVERAGE.md still lists as `unported` for this area.

| Group | Symbols |
|---|---|
| Detach | `DetachItemViaPointer` · `DetachItemFromArray` · `DetachItemFromObject` · `DetachItemFromObjectCaseSensitive` |
| Delete | `DeleteItemFromArray` · `DeleteItemFromObject` · `DeleteItemFromObjectCaseSensitive` |
| Insert | `InsertItemInArray` |
| Replace | `ReplaceItemViaPointer` · `ReplaceItemInArray` · `ReplaceItemInObject` · `ReplaceItemInObjectCaseSensitive` |
| Setters | `SetNumberHelper` · `SetValuestring` |

---

## 1. What the spike found

**Evidence, per hazard** (the shape `skeleton/SPIKE.md` now requires, added here
retroactively — this table is LESSONS #38's whole point). `ran:` means the named
committed program produced the quoted output on this machine; `read` means
someone looked at the source and reasoned. The first version of this section
opened *"everything below was executed under ASan/UBSan, not inferred from
reading"*, which was true of H1–H3 and false of H4–H6 — and H6, the only `read`
row that made a safety claim, was the one that was wrong.

| # | Hazard | Evidence |
|---|---|---|
| H1a/H1b | `DetachItemViaPointer` has no membership check | `ran: spikes/detach_null_write.c`, `detach_cross_document.c`, `detach_corruption_cashes_in.c` |
| H2 | `ReplaceItemViaPointer` shares the missing check | `read` — a design observation about the same absent invariant, not a claim that any particular call is safe |
| H3 | `InsertItemInArray` already has a corruption guard | `read` — quoting a guard that is present; nothing is called benign |
| H4 | `SetNumberHelper` has no NULL check | `read` — deliberately not run: the C's answer is a segfault |
| H5 | `SetNumberHelper` carries the same NaN→`int` UB | `ran` (as of module 12): pinned by `matrix-set.json`'s `set-nan-*` rows |
| H6 | `SetValuestring`'s length branch | `read`, **and it called the line memory-safe** — see H7 |
| H7 | the same `strcpy` is an OVERLAPPING copy | `ran: spikes/setvaluestring_alias.c` |

Reproducers are in the spike scripts described in §5.

### H1 — `cJSON_DetachItemViaPointer` never checks that `item` is a child of `parent`

This is the load-bearing hazard; three other symbols are thin wrappers over it.

The function (cJSON.c:2199) guards only `parent == NULL` and `item == NULL`.
It then unlinks `item` from whatever list it is actually in, and writes through
`parent->child` unconditionally in its "last element" branch:

```c
else if (item->next == NULL)
{
    /* last element */
    parent->child->prev = item->prev;    /* cJSON.c:2231 */
}
```

**H1a — NULL-pointer write.** If `parent` is an *empty* container
(`parent->child == NULL`) and `item` is the last element of some other list,
control reaches line 2231 and writes through NULL. Both arguments are valid,
live, non-NULL pointers obtained from the public API.

```
runtime error: member access within null pointer of type 'struct cJSON'
AddressSanitizer: SEGV on unknown address 0x000000000008
  The signal is caused by a WRITE memory access.
  #0 cJSON_DetachItemViaPointer c/cJSON.c:2231
```

**H1b — silent cross-document corruption, visible only later.** With a
*non-empty* `parent`, the same line writes a pointer from B's list into A's
`child->prev` — which is cJSON's *last-item cache*, the thing
`add_item_to_array` uses to append in O(1). Nothing looks wrong at the time:

```
A before:  size=2  [10,20]
B before:  size=2  [91,92]
detach B's last item, naming A as the parent  ->  returns non-NULL ("success")
A after:   size=2  [10,20]        <- unchanged, looks fine
B after:   size=1  [91]           <- silently modified; B was never named
```

One ordinary operation later, the corruption cashes in:

```
cJSON_AddItemToArray(A, 777)
A:  size=2  [10,20]        <- the append did not land here
B:  size=2  [91,777]       <- it landed in B
```

**A caller appended to A and the value went into a different document.** No
error, no crash, no diagnostic. This is the shape that decides §3.

### H2 — `cJSON_ReplaceItemViaPointer` shares the missing membership check

Same absent invariant, but it *does* guard `parent->child == NULL`, so H1a does
not apply. It frees `item` (`cJSON_Delete(item)`) after relinking, so calling it
with an `item` belonging to another parent frees a node that other parent still
links to — a **use-after-free primitive** rather than merely a wrong answer.
Not weaponized here; the port designs it out, and characterizing it further is
not what this spike is for.

### H3 — `cJSON_InsertItemInArray` already carries a corruption guard

```c
if (after_inserted != array->child && after_inserted->prev == NULL) {
    /* return false if after_inserted is a corrupted array item */
    return false;
}
```

Worth noticing rather than skipping: upstream added an explicit
*corrupted array item* check here. That is evidence this area has been bitten
before, and it is a partial defense against exactly the H1b state. It does not
generalize — `DetachItemViaPointer` has no equivalent.

### H4 — `cJSON_SetNumberHelper` dereferences without a NULL check

The **macro** guards it:

```c
#define cJSON_SetNumberValue(object, number) \
    ((object != NULL) ? cJSON_SetNumberHelper(object, (double)number) : (number))
```

…but `cJSON_SetNumberHelper` is itself `CJSON_PUBLIC` and exported, and its body
begins `if (number >= INT_MAX) { object->valueint = ... }` with no NULL test. A
caller who links against the symbol rather than using the macro gets a NULL
deref. The port has no NULL to deref, so this is a structural elimination — but
it must be *recorded* as one, not silently absent.

### H5 — `cJSON_SetNumberHelper` carries the same NaN→`int` UB already ledgered

Identical saturation block to `cJSON_CreateNumber` (cJSON.c:396 vs :2471).
`DIVERGENCES.md create-number-nan-valueint` covers the construction site and
explicitly defers this one; `oracle/make_fixed_core.py` deliberately does **not**
patch it, because patching code no module exercises adds an unverified branch to
the reference oracle (LESSONS #31). **This module patches that site and pins it**,
using the same corrected-oracle mechanism.

### H6 — `cJSON_SetValuestring`'s length-dependent in-place branch

```c
if (strlen(valuestring) <= strlen(object->valuestring))
{
    strcpy(object->valuestring, valuestring);   /* in place, buffer reused */
    return object->valuestring;
}
```

Shorter-or-equal reuses the existing allocation; longer allocates a fresh one and
frees the old. That is a real branch a differential must cross in both
directions, and the returned pointer's *identity* differs between the two paths
(same buffer vs new buffer) — invisible to a value-comparing differential, which
is worth stating rather than assuming away.

Note the interaction with interior NULs: a **parsed** string may contain a
NUL (`\u0000` parses), so `strlen(object->valuestring)` measures the truncated prefix while
the allocation is longer. The length comparison therefore uses a length that is
not the buffer's length. Memory-safe as written (the buffer is always at least as
long), but it is the kind of "two different notions of length" seam that
LESSONS #29 exists for, and the port must not accidentally use the full byte
length where the C uses the C-string length.

### H7 — the same `strcpy` is an OVERLAPPING copy, and H6 walked past it

**Added when the module landed (2026-09-07), because the spike got this one
wrong.** H6 looked at `strcpy(object->valuestring, valuestring)`, checked that
the destination is always long enough, wrote *"memory-safe as written"*, and
moved on to interior NULs. The buffer length was the wrong question.

Nothing stops `valuestring` pointing **into** `object->valuestring`:

```c
cJSON_SetValuestring(item, item->valuestring + 2);   /* strip a prefix in place */
```

Both arguments are valid, live pointers from the public API, the length test
passes (the suffix is shorter), and the copy is then an overlapping one —
undefined per C17 7.24.2.3, which `strcpy` inherits through its restrict-qualified
parameters. Confirmed, not argued:

```
ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges
  [0x504000000010,0x504000000033) and [0x504000000012, 0x504000000035) overlap
  #2 cJSON_SetValuestring c/cJSON.c:418
```

Reproducer: `spikes/setvaluestring_alias.c`. Recorded as FLAW-SCAN.md **L4** and
in DIVERGENCES.md under "Structural eliminations": the port's signature is
`set_valuestring(&mut Value, Option<&[u8]>)`, so the target is exclusively
borrowed for the call and the replacement cannot be a view into it — the borrow
checker rejects the aliasing at compile time rather than the library detecting it
at runtime, which it cannot.

**What the miss is worth noticing for.** This spike's whole premise is *execute
the C, don't reason about it* — §1 opens with "everything below was executed
under ASan/UBSan, not inferred from reading". H1–H3 were. H6 was not: it was read.
And the one hazard that was read is the one that was wrong, in a function the
Phase-0 flaw scanner had already flagged as a copy sink and this project had
already triaged as benign. The spike found the aliasing bug in
`DetachItemViaPointer` because it ran it; it missed the aliasing bug in
`SetValuestring` because it only read it.

---

## 2. The API-shape decision this forces

The C's mutation API is **pointer-identity based**: `DetachItemViaPointer` and
`ReplaceItemViaPointer` take a `cJSON *item` and rely on the caller to know it
belongs to `parent`. That is precisely the invariant H1/H2 show is unchecked.

The Rust port has **no way to express those two signatures faithfully**, and
should not try. `Value` is an owned tree with no parent pointers and no sibling
list; you cannot hold a reference to a child while separately naming its parent,
which is the borrow checker refusing to let the H1 state exist.

So the port re-expresses the surface as **index/key based**:

| C | Rust core |
|---|---|
| `DetachItemViaPointer(parent, item)` | *no direct analogue* — the aliasing it requires is unrepresentable |
| `DetachItemFromArray(arr, i)` | `detach_from_array(&mut Value, usize) -> Option<Value>` |
| `DetachItemFromObject(obj, key)` | `detach_from_object(&mut Value, &[u8], bool) -> Option<Value>` |
| `DeleteItemFrom*` | the same, dropping the result |
| `InsertItemInArray(arr, i, new)` | `insert_in_array(&mut Value, usize, Value) -> bool` |
| `ReplaceItemIn*` | `replace_in_*(&mut Value, …, Value) -> bool` |
| `SetValuestring` / `SetNumberHelper` | `&mut Value` in-place setters |

`*ViaPointer` therefore lands in API-COVERAGE.md as **`out-of-scope`, not
`unported`** — a deliberate Prime Directive refusal with a written reason (the
same category as `cJSON_InitHooks` and the borrowed-pointer `*Reference`
constructors), because reproducing it means reproducing an unchecked aliasing
contract whose failure mode is a NULL-write and a UAF primitive. That is a
decision to state loudly in the manifest, not a gap to leave implied.

**Consequence for the ratchet:** the module clears 14 symbols but only ~12 move
to `ported`; 2 move to `out-of-scope`. 18 → 4 either way.

**Consequence for the FFI crate:** the C-ABI shim exports the real symbol names
and cannot simply omit two of them. It must export `cJSON_DetachItemViaPointer`
and `cJSON_ReplaceItemViaPointer` and make them *safe* — verifying membership by
walking the parent's children and returning NULL when `item` is not among them.
That is a **deliberate behavioral divergence** (the C corrupts; the port
refuses), it is observable, and it needs its own ledger entry with the
`lib_diff` vectors to pin it. This is the single biggest piece of work in the
module and the reason it should not be bolted onto another one.

---

## 3. Does it need a mutation-sequence fuzzer? — Yes, and H1b is the proof

Every mode so far is single-shot: one input, one operation, compare. That would
report **MATCH** on the H1b detach — both sides "succeed" and A prints unchanged.
The divergence only appears on a *later, unrelated* operation.

A differential that cannot express "do X, then do Y, then look" cannot see this
class at all. So the module needs a mode whose input is a **program**:

```
<json document>
<op>\t<arg>...
<op>\t<arg>...
...
```

with the descriptor emitted **after every step**, not only at the end — a bug
that corrupts state at step 2 and is masked by step 5 must still be caught. Each
op line is one mutation entry point; the trailing observation reuses the
`access` descriptor from module 10, which is exactly why the accessors were
ported first.

Design constraints for that mode, learned from the modes already built:

- **Decide the framing before mutating shared input** (LESSONS #27). This mode
  parses more of stdin than any other; it must be a self-contained early return
  in `driver.c`, like `access` and `construct`.
- **Ops must be reachable but bounded.** Cap the program length; an unbounded op
  list makes the descriptor unbounded and the fuzzer slow.
- **Do not build the H1 state deliberately.** The port physically cannot enter
  it, so a sequence that requests it can only ever diverge. Either the op
  encoding makes cross-parent targeting unrepresentable (preferred — the ops are
  index/key based, so it falls out for free), or every such sequence needs a
  ledger entry, which is the unpinnable-class trap again (LESSONS #28).
- **Expect a corrected oracle.** H5 alone guarantees one: `make_fixed_core.py`
  gains the `SetNumberHelper` patch, and the fixed-oracle build already supports
  multiple corrections as of LESSONS #36.

---

## 4. Proposed module split

Not one module. Three, in dependency order, each independently gateable:

1. **`dom-mutate-remove`** — Detach + Delete (7 symbols, minus the 1 refused).
   Carries the sequence-mode harness itself, so it is the expensive one. Land
   the mode with the smallest op set that can demonstrate H1b's absence.
2. **`dom-mutate-place`** — Insert + Replace (5 symbols, minus the 1 refused).
   Reuses the mode; adds ops. H3's corruption guard and H2's free-on-replace are
   the interesting behaviors.
3. **`dom-mutate-set`** — the two setters (2 symbols). Independent of the other
   two and much smaller: H6's length branch and H5's ledgered NaN. Could ship
   first if a quick win is wanted, since it needs no sequence mode at all.
   **LANDED 2026-09-07.** It shipped first, for that reason. Two things it found
   that this list did not predict: H7 (the overlapping `strcpy` H6 walked past)
   and `cJSON_SetNumberHelper`'s missing TYPE check, which is a second ledgered
   divergence class beside H5's NaN — the C leaves a `cJSON_String` node carrying
   a number, and the port cannot represent that at all. The estimate that this
   was the small one held; the estimate that it was the *boring* one did not.

Estimated risk order: (1) ≫ (2) > (3). Almost all of the uncertainty is in
building the sequence mode, which is why it gets its own module rather than
riding along.

---

## 5. Reproducers

**`bash spikes/run.sh`** rebuilds all three under ASan+UBSan and re-derives every
result quoted above. They are committed rather than left in the session that
wrote them: this document makes claims about a dependency's behavior, and a
claim whose evidence lives only in an ephemeral container is one nobody can
re-check later (LESSONS #32).

| Spike | Demonstrates | Result |
|---|---|---|
| `spikes/detach_null_write.c` | H1a: empty parent + last-of-other-list item | ASan SEGV, WRITE, cJSON.c:2231 |
| `spikes/detach_cross_document.c` | H1b: cross-document detach, immediate view | B silently modified, A "fine" |
| `spikes/detach_corruption_cashes_in.c` | H1b one op later | append to A lands in B |
| `spikes/setvaluestring_alias.c` | H7: in-place prefix strip via `SetValuestring` | ASan strcpy-param-overlap, cJSON.c:418 |

They are **not** gates — `check.sh` does not run them and three are expected to
abort. When the module lands, each behavior becomes either a probe (for what the
port reproduces) or a ledger entry with a pinned fingerprint (for what it
refuses).

When the module lands, each becomes a probe (for the behaviors the port
reproduces) or a ledger entry with a pinned fingerprint (for the ones it
refuses).

---

## 6. A note on upstream

H1a, H1b and H7 are defects in a currently-shipping, widely-vendored MIT library,
and this document characterizes them only to avoid reproducing them in the port — the
Prime Directive's *"the C is a specification that may be buggy; do not faithfully
re-implement a vulnerability."*

Whether to report them upstream is the maintainer's call, not this port's, and
nothing here has been sent anywhere. If it is wanted, the material is ready: the
four reproducers, their ASan traces, and the one-line invariant missing from each
(`item` must be reachable from `parent->child`; and `cJSON_SetValuestring` must
use `memmove` semantics, or reject a `valuestring` inside its own buffer). Flagging it here so the decision
is made deliberately rather than by default.
