# Phase 0 — C-flaw inventory (<library> <version>)

Template. Replace the angle-bracket placeholders; keep every heading, including
the two that exist to stop this file from overclaiming.

Produced by `harnesses/c-flaw-scan/scan_c_flaws.py`, which the port's `check.sh`
re-runs **every gate** (not once at Phase 0) — the C in scope grows as modules
land, and a newly-vendored source must not arrive un-triaged (LESSONS #31).

## What the scan covers, and what it cannot

State this before any finding. The scanner is a **fast grep-shaped heuristic**
over copy sinks, format strings, integer-overflow multiplications, command
execution, TOCTOU and stack VLAs. It cannot see logic errors, missing
preconditions, type confusion, undefined behavior in arithmetic, or anything
requiring the code to actually run.

> **Reach:** `<N>` files, `<M>` lines, categories `<...>`. Findings below are
> *by this method over this code* — the absence of a finding is not the absence
> of a flaw.

## Scanner hits — triage

| # | Site | Category | Real? | Port's answer |
|---|---|---|---|---|
| | | | | |

Triage every hit: does the Rust port close it structurally, or does it need a
deliberate fix? A confirmed flaw the port fixes gets a `DIVERGENCES.md` entry, so
the fix is planned, surfaced, and shipped as a release note — never silently
patched.

## Historical CVE / security record

From the upstream CHANGELOG / advisory feed. **The port MUST preserve every
fix** — a rewrite that reintroduces a patched CVE is the worst outcome available.

| CVE / commit | What it was | How the port preserves the fix |
|---|---|---|
| | | |

## Live defects found by PROBING, not by the scanner

**Required section. Leave it present and empty if there is nothing to record.**

LESSONS #37: a flaw record that only contains what a regex can see is measuring
the regex. In practice the real findings come from *running* the C — under
sanitizers, or the moment a module puts an entry point on the compared contract
and the differential disagrees. Record those here, with a reproducer committed
under `spikes/` so the claim can be re-checked after this session ends
(LESSONS #32).

| # | Where | Class (CWE) | Status |
|---|---|---|---|
| | | | |

If any entry is a live defect in a currently-shipping dependency, say explicitly
whether it has been reported upstream. That is the repo owner's decision, not the
port's — but silence must not be allowed to look like a decision.

## Net Phase-0 security posture

Conclude here — and **scope the conclusion to the method**. "No live bugs found"
is a statement about the scan's reach; written unqualified it survives as a
statement about the library, and the port plan and threat model both get built on
top of it. Say which guards Rust does *not* give for free (these must be
replicated deliberately) and which classes it eliminates structurally.

Revisit this section whenever the "live defects" table above gains a row: a
posture conclusion that was accurate at Phase 0 can become false later, and
correcting it in place is worth more than the original conclusion was.
