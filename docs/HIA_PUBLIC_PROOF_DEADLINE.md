# Public proof absolute deadline profile

The public proof front-end preserves the original method's error ordering while
retaining its original proof budget. Admission, normalization, required detailed
diagnostics, schema checks, entry selection, exact signatures and profile checks
finish before an elapsed proof deadline may replace their result. A deadline is
never renewed at a child boundary. This is a qualified component, not a claim
that the complete public API or native release is finished.

## Primitive request

`HIAMVP01` remains unchanged. `HIAMVP02` has the same 64-byte header and tails:
magic, mode, configured timeout in milliseconds, name length, before length,
after length, zero, and the parent's absolute monotonic deadline in nanoseconds.
The tail remains name + before + after. The original mode, name, Core size and
1–60000 ms bounds remain unchanged. The final word may be zero or already in
the past. It may not exceed the receiving child's current monotonic time plus
the original configured timeout. Overflow and nonzero reserved fields refuse.

The new profile freshly verifies both translation inputs and completes original
schema/selection/signature/profile precedence before checking that absolute
deadline at solver entry. Solver work, replay and final identity checks all use
the same deadline. A result already proved or disproved that finishes late is
demoted and its true proof claims are cleared. An unresolved, expired query
retains its actually completed structural/canonical verification, matching the
original proof finalizer. Identity failure still clears those claims. The old
`HIAMVP01` behavior is unchanged.

## Parent transport lifetime

The `HIAPPR01` parent records its proof start once. It passes the original
configured timeout and this immutable absolute deadline to `HIAMVP02`; it does
not round remaining milliseconds into a new child budget. Invalid input and
other preceding unknown results are not overwritten merely because they took
longer than that proof budget. A positive result cannot survive a late parent
completion. Reported wall time includes the actual parent operation.

Child transport has one separate operational deadline, computed once as the
original proof deadline plus 60 seconds. This permits the bounded normalizer
and diagnostic producer to finish the required preceding work. It is never
renewed for the second input, diagnostics or proof child. Exhaustion is an
unavailable-checker result, not evidence of a mathematical proof. This allowance
does not change any solver timeout, cold qualification budget, input/node limit
or captured-stream capacity. Maximum-byte and near-maximum-node inputs and the
function/block boundaries were executed against the actual original normalizer;
these measurements support the operational bound, not an exhaustive worst-case
time theorem under arbitrary host scheduling.

## Evidence and limits

The exact new primitive image passed the original 113 semantic calls, 100
refusal-order comparisons and 68 private process/packer checks. The same 100
original refusal cases also passed with an already-expired absolute deadline.
Forty-three additional controls cover endpoint arithmetic, preserved reserved
fields, expired valid queries and actual process refusals. The actual complete
parent passed all original 113 semantic calls, including their original default
budgets and concurrency controls.

Twelve actual parent/original comparisons combine 8 MiB invalid input, invalid
second input, valid input and fresh receipt verification with 1, 2 and 2000 ms
budgets. Every original claim key is compared. For the large valid case, the
report preserves the fresh original outcome and a separate original run with
validation deliberately delayed past its original deadline; this distinguishes
error-order semantics from a performance claim. Parents in this matrix execute
from once-captured, mode-0500, seal-15 memfds. All raw output is retained.

Earlier failed development evidence is retained: the first absolute profile
cleared canonical verification on unresolved expiry; that mismatch was fixed
without changing the original expectation. A separate path-executed parent
reported identity-unavailable once; its cause is not established, the identity
rule was not relaxed, and the same image/input plus the sealed matrix passed.
The JSON record identifies these failures and all current image/source/report
pins. Typed empty/non-ASCII/non-string function arguments, complete parent
cancellation/fault coverage and full MV/publication integration remain open.
