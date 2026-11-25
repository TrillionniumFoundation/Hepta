# Native decimal selection and owned BG snapshots

This checkpoint extends the actual HIA runtime effects with HIAMVEX2. Existing
HIAMVEX1 behavior and its bounded structural frame remain unchanged. The complete
public runtime, full public snapshots/errors and fixed BG provider are still
being integrated; whole_native_runtime is false.

## What is actual

Expected generation and epoch are canonical nonnegative decimal spans of arbitrary
numeric width. The owner obtains the writer lock before comparing them, then uses
the same selection lock and immutable identity owner as publication. A successful
comparison retains both actual identity objects until preparation ends. The
coordinator consequently compares strong object identities at the final commit;
it does not wrap a public number or trust a caller-supplied private identity.

The BG snapshot is copied under that same selection lock. It includes complete
current generation/epoch decimal bytes and actual baseline/current Core, original
input and artifact SHA values. Its freshly allocated bytes remain owned by the
receiver after the lock is released. This is the existing HIAMVBS1 BG projection,
not a replacement for the original complete runtime snapshot.

## Private frame and ownership

HIAMVEX2 retains the 256-byte header and existing raw/parent/function/argument/
measurement span layout. Only operation 2 (conditional publication) and operation
14 (BG snapshot) use this magic. For operation 2, private expected identity words
at 40 and 48 are zero. Lengths at 224 and 232 describe generation and epoch decimal
spans appended after all existing spans; 240 and 248 are zero. Both decimals are
nonempty canonical ASCII digits, with no leading zero except the value zero.
Arithmetic on byte extents is checked before access. There is no u64/128-bit
numeric ceiling. Other Core/measurement and process-image bounds are unchanged.

Operation 14 has no tails. Success returns the existing HIAMVER1 header with
malloc-owned projection pointer/length at 144/152. The receiver must capture it
and free that one allocation exactly once. Failure does not transfer a partial
projection. Existing HIAMVEX1 callers receive zeros in these added fields.

Conditional publication keeps the original clock, writer wait, closed/stale,
cancellation, budget, capacity, admission, proof, build, final comparison and
token-commit sequence. On a failed second retain, the first actual reference is
released. An unexpected ownership-release failure is fenced and the reference
is retained in runtime custody rather than forgotten.

## Qualification and limits

The accompanying JSON embeds the complete actual records and all source/role/
object/image pins. Seventeen original-runtime state comparisons and 48 native
calls pass, including actual generation-(2^128+17).so construction, rollback ABA,
cancel/budget/committed-token priority, a 16,385-digit epoch snapshot and complete
comparison/carry. The decimal values are created and retained by the real native
value owner; a privileged QA seed places counters at boundaries unreachable in a
short test. The independent Python runtime is seeded to the same mathematical
values for its own actual calls.

Concurrency includes a conditional publication waiting behind a real writer,
two real writers competing for the same snapshot, and 400 snapshots from four
readers while real build/selection/retirement proceeds. The four groups contain
426 actual native calls and 61 malformed-decimal/extent/atomic-output guards.
Four actual malloc controls/failures cover snapshot allocation and each expected
identity retain. Every failure preserves the same runtime's usability and exact
FD/artifact/allocation ownership.

The changed image also passes all six existing strong-reference concurrency
groups (3,446 calls) and seventeen original runtime effect observations (47
calls). Pure HIA packers and the existing closed linker constructed both effects
and handles images. Reconciled build records reread actual object and role bytes;
older inherited development metadata is preserved but is not treated as current.

The first diagnostic QA failure was an insufficient output buffer in the QA
observer, not a product refusal of the long value. Its evidence remains intact.
No default limit, expected error, public numeric bound or original test was
relaxed to pass this checkpoint.
