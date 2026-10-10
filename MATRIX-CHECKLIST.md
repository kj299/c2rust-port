# Designing the differential matrix

Detail pushed out of PLAYBOOK Phase 4, steps 2 and 3, which keep a summary and
the lessons they cite. A green differential is a statement about the matrix, not
the port: it checks the inputs the matrix holds (LESSONS #6). Each item below is
an input that tells two readings of a rule apart, and each was learnt the
expensive way, on the cJSON port here or on the lsof line's port, lsof-rs: a rule
written from a model of the C, matched on every case the matrix could spell, and
wrong on the first case it could not.

## The surface the matrix must reach

- **Every public entry point the module claims** is called by some driver mode
  (LESSONS #26), and every exported symbol is accounted for in
  `API-COVERAGE.md`, which `harnesses/api-coverage/check_api.py` holds to the
  headers (LESSONS #34, #35). A gate judges only the surface the driver exposes.
- **Every module has probes**, and `probe.py coverage` fails one that has none
  (LESSONS #23).

## State no output reads

**Ask what state the C keeps that no output depends on** (LESSONS #39): a
last-item cache, a length beside a pointer, a memoized count, a free list, a
dirty flag. A value-comparing differential never reads any of it, so the mode
must contain the operation that *consumes* it, or the gate goes green over a
field nothing touched. cJSON's `parent->child->prev` is such a cache: a detach
rewrites it, nothing printable depends on it, and only an append reads it back.
If the mode is multi-step, emit the descriptor after every step: a corruption at
step 2 that step 5 masks is invisible to a final-state comparison.

## Inputs that tell two readings apart

- **A fallback is a feature of its own** (LESSONS #53). For each fallback,
  exemption or second matching rule, name the input it is for, and give the
  matrix a case where it must fire for that input and one where another input
  must not reach it. lsof-rs compared NAMEs to find sockets by path; a socket's
  NAME carries a `type=` tail, so the comparison never found one and fired only
  for a file of the same name in another mount namespace.
- **An empty list item is input too** (LESSONS #56). For every list-valued
  input: an empty item in each position (`,`, `,x`, `x,`, `x,,y`), a lone
  prefix (`^`), a separator the oracle does not name, a repeated option, and
  items of mixed kinds. lsof-rs split its lists with
  `filter(|s| !s.is_empty())`, and the C read an empty `-p` item as PID 0.
  Measure the oracle on each before writing the parser.
- **Spell a path every way a user types it** (LESSONS #56): relative (a case
  names the directory it starts in with `cwd`, which `diff_run.py` honours), `.`,
  `..`, doubled and trailing slashes, links with relative and absolute targets,
  a link's own text. Where the C spells or parses an input with a helper of its
  own (lsof's `Readlink()` for `realpath()`), port the helper, and use the
  library's only where it is shown equal; for a helper that is pure, compile the
  C's own function into a harness (`harnesses/cando/`) and fuzz the port against
  it.
- **A silent case needs a reason to be silent** (LESSONS #56). A case whose
  expected outcome is silence — an error exit, an empty listing, a suppressed
  column — can be met by many wrong programs: lsof-rs's `lsof -K x` case
  compared an empty stdout and an exit 1 that the two binaries reached for
  opposite reasons. A case that claims something about what is listed needs
  something to list that the claim would change, and a recorded C defect that
  depends on where an argument stands needs the options first, where the C reads
  them as options.
- **A fixture changes what other cases see** (LESSONS #56). A fixture that
  changes shared state — the mount table, `/dev/shm`, a sysctl, the lock table,
  an environment variable a later case inherits — is an input to every case.
  Give what it makes names nothing else uses, undo it in the harness's
  `finally`, and judge a new fixture by the whole matrix, never by its own cases.

## Where the matrix runs out

The matrix holds the cases someone thought of. Fuzz the same inputs into the
oracle and the port with `harnesses/diff-fuzz/diff_fuzz.py`: on stdin, or, for a
command-line tool, on argv, from the C's own option letters
(`--argv-inventory`, LESSONS #59). Its first run against lsof-rs found four
divergences no case had.

**Against a corrected oracle.** A *predicate-defined* divergence — one that
fires for a whole class of inputs rather than a nameable few — has no finite
fingerprint set, so it needs a corrected reference oracle: a patched copy of the
C that shares the port's decision, with the class asserted finitely against the
PRISTINE oracle in the matrix (LESSONS #28). Then measure how wide that patch is
(LESSONS #42): it is code you wrote against the subject under test, and if it
suppresses more than the ledgered class it suppresses real findings invisibly —
a clean report is this control's failure mode. So fuzz the same mode against the
pristine oracle too, classify every finding mechanically, not by reading the
first few hunks, and record both runs side by side. That measures width;
**completeness** has no control (LESSONS #43): a route no mode calls yields zero
findings against both oracles. When a change puts a new entry point on the
contract, enumerate by call graph which existing corrections it reaches and
re-derive them; keep a per-correction table of routes and the mode that
exercises each.

## Proving the cases

Mutate the rules the cases are for (LESSONS #58): one plausible wrong version of
each, committed as a mutants file beside the cases and run with
`harnesses/port-mutation/mutate_port.py`. Every mutant must be KILLED. A
survivor is a case that checks nothing; an edit that does not apply, or a mutant
left in place, is refused by the harness rather than read as a result, and a run
killed outright leaves a journal that `--restore` undoes. Run `--apply-only` on
every change so the committed mutants still fit the code, and `--check-clean`
whenever you need proof that none is left in the tree.
