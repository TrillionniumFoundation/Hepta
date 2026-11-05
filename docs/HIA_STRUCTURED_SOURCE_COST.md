# Structured source validation cost

This change optimizes pure parsing and value reconstruction inside the existing
source validators. It does not remove a validator invocation, add an acceptance
cache, change generated Lean bytes, change a proof budget, or grant native or
production authority.

## Complete expression token coverage

The prior tokenizer repeatedly called the same regular expression at the next
unconsumed position. The new implementation first uses an anchored full match of
the same nonempty token pattern with possessive repetition, then obtains the
ordered token captures in a second C-level pass. Each greedy token is committed
before proceeding, matching the old adjacent-match loop. Empty input, invalid
gaps, unsupported characters, and trailing whitespace retain their old outcomes.
The fixed Python 3.12 toolchain supports the possessive quantifier.

An initial candidate used unanchored substitution to detect gaps. Independent
review found quadratic scanning on invalid whitespace suffixes. That candidate
was withheld; its source and counterexample evidence are retained separately.
The committed version rejects such input in the anchored coverage check before
starting a nonanchored search.

## Per-invocation decoded alias values

The expression parser constructs exact builtin values and `_Raw` objects. It
only reads previously published aliases; list prepend and append make fresh
lists. One `verify_structured_source` invocation therefore has a read-only alias
DAG. Its private decoder reuses a decoded value only for the identical parsed
object, after all recursive domain and key-order checks have succeeded. Entries
hold a strong reference to the original object so temporary wrappers cannot
collide through Python object-id reuse. Failed and partially checked parents are
not inserted.

Every alias is still checked at the same call site. The table is new for each
complete verification, cannot be supplied by a caller, contains no acceptance
result, and is discarded when that verification returns. Every subsequent full
source reconstruction independently parses and checks the actual source again.

The caller-facing comparison against `expected_tree` deliberately continues to
use the original recursive `_raw_value` on a fresh value. A custom caller
equality method can mutate an object it receives, so no private cached list or
dictionary is exposed at that boundary. Internal subtree comparisons use the
separate tree reconstructed from the authenticated byte stream. Independent
review found and demonstrated this issue in the withheld initial candidate; the
adversarial full-verifier regression fails on that candidate and passes after the
fresh comparison is restored.

## Verification and limits

Raw strings retain the exact builtin-list/builtin-integer domain and the same
printable ASCII set excluding quote and backslash. C-level exact-type iteration,
byte construction, and deletion of the allowed byte set replace the Python
per-character predicate. Boolean values, integer subclasses, out-of-range bytes,
and forbidden printable bytes are still rejected.

Repeated theorem-header queries use an index of all literal `theorem ` candidate
starts, including embedded and non-line-start occurrences. The next literal
ASCII space forms the lookup key. Every candidate still undergoes an exact
`startswith` check, and matches obey the same non-overlap rule as `str.count`.
Other literal forms fall back to `str.count`. No identifier normalization or
line-boundary assumption changes the old rejection behavior.

The dedicated controls compare the old and new expression parsers on exhaustive
short strings, seeded mixed syntax, Unicode whitespace, invalid gaps and long
suffixes. They also cover shared Raw DAGs, exact type/range rejection, duplicate
or unordered object keys, temporary-wrapper identity, failed-parent insertion,
changed source under a recomputed manifest, and malicious caller equality.

The existing complete original-source inverses, actual declaration checks,
manifest checks, source/tool byte rereads, stage receipts, Lean stages, and final
independent replay remain mandatory. A preserved module-hash comparison is
evidence of this concrete transformation, not a general theorem about all input
programs. Complete qualification must still finish within the unchanged budget.
