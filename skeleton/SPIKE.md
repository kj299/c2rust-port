# Spike — <the scary thing>, before scheduling it

Template. Replace the angle-bracket placeholders; keep the **Evidence** column
and the closing rule, which exist to stop this document from lending its
executed claims' credibility to its read ones.

**Status: design spike, not a port.** Nothing here is ported. Its job is to
answer, before a module is scheduled: what are the hazards, how should the work
be split, and does the module need harness machinery no existing mode has.

Written because the kit's most expensive habit says so — *"spike the scary module
before scheduling it"* (CLAUDE.md, "Habits the retrospective bought in blood").

Scope: `<the N symbols / syscalls / entry points this covers>`.

## The hazard log

**Every row carries its Evidence.** `ran: <reproducer>` means a committed program
under `spikes/` produced the quoted result on this machine. `read` means someone
looked at the source and reasoned. Both are legitimate; conflating them is not
(LESSONS #38 — the one hazard that was read instead of run is the one that was
wrong, in a function a previous pass had *also* read and called benign).

| # | Hazard | Evidence | What the port does |
|---|---|---|---|
| H1 | | `ran: spikes/<x>.c` | |
| H2 | | `read` | |

Then write each hazard up below the table, quoting the actual output for every
`ran:` row.

## The rule for a `read` row

A row you are about to call **benign** may not stay `read` without saying what
you did not try. Write the one sentence: *"not executed; the case that would
disprove this is `<...>`"* — and if you can think of that case, it is usually ten
lines and one compile, so run it and change the row to `ran:`. If you genuinely
cannot construct one, that sentence is far more useful to the next reader than
the word "safe".

Reasons a `read` row is fine: the behavior is a compile-time property, the
platform to run it on is not available here, or the hazard is a *design*
observation rather than a claim about what the code does.

## The API-shape decision this forces

Where the C's signature encodes an invariant it does not check, say so, and say
what the port's signature is instead. A contract the port **cannot express** is a
Prime Directive refusal — it belongs in `API-COVERAGE.md` as `out-of-scope` with
a written reason, not as `unported` backlog.

## Harness machinery the module will need

New driver mode? Sequence rather than single-shot? A corrected reference oracle
(LESSONS #28) because a divergence class is predicate-defined? Decide here, not
mid-module.

## Module split

Not one module if it can be several. Give each one its symbols, its dependency
order, and an honest risk ranking — the point of the ranking is to let the
cheapest one ship first and the expensive one carry the new harness.

## Reproducers

Commit them under `spikes/`, with a `run.sh` that rebuilds every one under
sanitizers. A spike makes claims about a dependency's behavior, and a claim whose
evidence lives only in the session that produced it is one nobody can re-check
(LESSONS #32). They are **not** gates: `check.sh` does not run them, and some are
expected to abort.

| Spike | Demonstrates | Result |
|---|---|---|
| | | |

## Upstream

If any hazard is a live defect in a currently-shipping dependency, say
explicitly whether it has been reported. That is the repo owner's decision, not
the port's — but silence must not be allowed to look like a decision.
