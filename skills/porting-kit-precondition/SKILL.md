---
name: porting-kit-precondition
description: Reshape the C in C (behavior-preserving) BEFORE any Rust, so it translates into safe Rust cleanly. Use in Step 0 — after Phase 0-1, before the oracle and translation — to localize global state into a threaded context struct, reduce aliasing, and settle the #ifdef story. Each move is verified against the existing C test suite before you touch Rust.
---

# Porting Kit — precondition the C (C→C, before any Rust)

Wraps `porting-kit/C-to-Rust-Playbook-Best-of-Both.md` **Step 0** and PLAYBOOK
Phases 0–1. Read those first. The most portable finding in the TRACTOR report:
reshape the C so it maps onto *safe* Rust, verify with the C's OWN test suite, then
translate. Every move here is a **behavior-preserving C→C refactor** — if you can't
show it preserves behavior on the existing C tests, don't make it. Preconditioning
is safe precisely because it is checked while the C is still the reference.

## Preconditions
- Phase 0 inventory done and `porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py`
  run; Phase 1 order chosen. Precondition per subsystem, in that order.
- A runnable C test suite. If there isn't one, capture the reference behavior first
  with `porting-kit/harnesses/golden/golden.py capture` so each refactor can be
  replayed against it — a refactor you cannot check is a guess, not a refactor.

## The three moves (verify on the C tests after each, before the next)
1. **Localize global state into a context struct.** Gather every mutable global (and
   its type closure) into one struct, instantiate it once in `main`, and thread a
   pointer through the call graph. Why it pays off downstream: a global that reaches
   Rust as `static mut` is `unsafe` at *every* access; the same state threaded as a
   struct field becomes an ordinary `&mut` borrow. For a global you genuinely cannot
   thread, decide its Rust landing now — `Cell`/`RefCell`/thread-local, never
   `static mut`.
2. **Reduce aliasing pressure.** Lift subfield arguments (`foo(x, x->y)` →
   `foo(x, tmp)`), split multi-variable declarations, and turn pointer arithmetic
   into array indexing. These are exactly the shapes the borrow checker rejects
   later; fixing them in C keeps the translation mechanical instead of a fight.
3. **Settle the macro / `#ifdef` story — deliberately.** Preprocessor-driven
   translation silently collapses the build to ONE configuration and discards the
   other `#ifdef` paths. Decide now: translate each configuration and merge under
   Rust `#[cfg]`, or consciously pick one and DOCUMENT what is dropped. Never let a
   configuration vanish by accident.

## Then hand off
Once a subsystem is preconditioned and green on the C tests, hand off to
`porting-kit-oracle` (build/extend the differential vectors on the preconditioned C)
and then `porting-kit-module` (translate through the six gates). If a precondition
move surfaces a latent C flaw, triage it into `DIVERGENCES.md` like any other
fix-of-C-defect rather than faithfully carrying it across.

## Integrity
Paths/commands must match the kit and `C-to-Rust-Playbook-Best-of-Both.md` Step 0 /
PLAYBOOK Phases 0–1. Fix the reference on drift and re-run the kit's `make check-kit`
(`make -C porting-kit check-kit` when vendored).
