# Isolated byte-bound Core syntax checker: implementation status

UNCHECKED Lean text. Python/mock tests do not establish any kernel theorem.
This implements the first bounded stage of CORE_SYNTAX_CONNECTION.md on one
actual linear slice, not all eight workload slices. The full linear Core is
retained rather than a slice-only tree. No production code or gate is changed.
All twelve global obligations remain unproved, all admission flags false and
DENY_ALL. It does not prove actual VM execution or initialization elision.

## What the kernel is asked to check

CoreSyntaxSlice.lean adds a restricted inert Raw tree. Its serializer uses
canonical compact JSON punctuation, nonnegative decimal integers, sorted unique
object keys and printable ASCII strings excluding quote/backslash. An independent
fuelled decoder must return the same Raw tree before checkedEncode succeeds.
The generic roundtrip theorem then proves that two accepted encodings of the same
bytes have identical trees. This is checked roundtrip determinacy, not assumed
serializer injectivity or completeness for arbitrary JSON.

Nat byte lists must contain only values <=255; there is no UInt 8 literal coercion
or modulo alias. Whole-tree bounds are 4096 nodes/depth 32/32768 bytes. Python's
producer further restricts integer literals to 0..2^64-1, while the inert Lean
transport permits larger Naturals within its byte/fuel budget. No scalar value
claim follows from transport alone. Partial parser/serializer fuel exhaustion
refuses; it is not an acceptance of malformed input.

The Lean reconstruction reads actual functions, block inventories, ordered
parameters/definitions, comparison, condition, then edge, actual addition and
its earlier constant. It proposes a Descriptor and separately checks the
explicit SliceSyntaxRelation. The relation does not call reconstruct or extract.
Generic extract_sound derives the declared relation from acceptance; composition
reuses the existing selected_successor theorem. This is checker soundness for an
explicit syntax contract, not a theorem about Python or Core runtime semantics.
Unknown body operations remain inert and losslessly present, never assumed no-ops.

The actual byte input is canonical verify_program output, not the original source
or pre-canonicalization JSON. Python strict_canonical checks original supplied
transport bytes before object folding, rejecting duplicate keys, signs, floats,
leading zeros, Unicode/escapes, bool/null and noncanonical whitespace/order.
It independently re-parses the emitted exact Nat-byte numeral payload and compares
it byte-for-byte with the fixed input. Full canonical bytes are regenerated and
compared before/after execution. File provenance and source/lowering/verification
correctness remain external trusted boundaries, not kernel results.

## Concrete controls and scope

The inherited #600 positive input retains its 56 named generic/descriptor/witness
checks. Four new generic theorems plus five concrete certificates bring this lane
to 65 exact named axiom checks:

- Full real linear Core byte certificate, first-slice extraction, structural relation.
- Full reverified variant with swapped same-typed else-arm arguments, while the
  then arm is unchanged: independent byte and extraction certificates.

The variant retains distinct branch targets so the original Core remains reachable;
it is not claimed as a same-target runtime test. It ensures the negative which
changes reconstruction from then to else is observable. Eight other real slices
are not newly syntax-certified here. The inherited scalar small/upper witnesses
still establish nonvacuity for the selected descriptor, not actual body arrival.

Ten fixed negatives: one exact byte change; a stale proposed descriptor; duplicate
keys; unordered keys; byte 256/modulo alias; leading-zero parser spelling; three
reverified actual-Core mutations (wrong phi, literal two, condition); and a Lean
reconstruction mutation selecting else instead of then. Each now requires an exit-zero kernel certificate of the exact original wrong
proposition's negation, with the unique intended_rejection axiom inventory and
no errors or sorryAx. The three new mutant inputs first prove their independent
transport equality. Any syntax/import/missing-tool/resource error fails the run;
no compiler error counts as a successful rejection. Reports retain original
proposition, input hash, certificate kind and checked flag, including failures.

There are 35 new Python controls: 24 transport/boundary tests and 11 generated-input
or mocked-runner tests. Their mocked results are explicitly not kernel evidence.
The combined Python lane has exactly 155 tests with no skips or expected failures.
It retains the prior tests rather than replacing them with these narrower controls.

## Resource and CI boundary

The producer checks individual generated proof text incrementally at 2MiB and
aggregate retained proof inputs at 8MiB. Transport rejects overlarge trees before
literal expansion, including oversized strings and pending node inventories.
The initial actual inputs are approximately 250KiB positive and 1.4MiB aggregate;
those are proof artifacts, not performance measurements of Hepta programs.

The new read-only exact-HEAD lane reuses the existing SHA-locked Lean 4.19.0
bootstrap/support inventory. Eleven kernel invocations have existing 60-second
per-process limits, a 540-second new-invocation deadline, an external 600-second
command limit and 15-minute job limit. Generated inputs/results remain in the
runner's temporary directory; diagnostics are printed to CI logs only. No artifact
upload, target compiler, target execution or local software installation is added.
Source/model/workflow and prior proof dependencies are hash-bound before/after.
Host/I/O and dependency acquisition trust remain as in the existing checker.

No local Lean is available. Mutual equality decision elaboration and concrete
kernel reduction cost have not been tested; only actual pinned CI can accept or
reject these texts. Preserve failures and do not increase limits or use
native_decide as a substitute for a kernel-checkable result. Review is required
before publication/CI. Even successful CI would only establish this restricted
byte-bound syntax connection to a projected theorem, not complete any of the
twelve Core/runtime/body-prefix/all-edge/resource/loop/backend obligations.


## First real kernel failure and proof-protocol repair

Head 5e740715e90036a55480685c8da1cf12d9c4cfe4, actual run
[41643195183/job125941651738](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41643195183/job/125941651738),
failed its positive stage. A doc comment before mutual and reserved helper name
at caused parsing errors; extract_sound did not unfold its let before splitting;
large concrete transport checks exceeded the elaborator's default recursion
bound. No negative was counted. The original log and failed result remain in CI.

The repair changes the comment/helper spelling and the same theorem's proof
structure without changing statements or the declarative relation. Concrete
certificates use `decide +kernel`, which sends the proof term directly to Lean's
kernel rather than first reducing it with the elaborator. This is NOT native
execution or native_decide, and no input, recursion, heartbeat or time budget is
increased. The exact pinned implementation is
[Lean v4.19.0 ElabTerm.lean, evalDecideCore/doKernel](https://github.com/leanprover/lean4/blob/v4.19.0/src/Lean/Elab/Tactic/ElabTerm.lean#L404-L451);
[its syntax/configuration is in Init/Tactics.lean](https://github.com/leanprover/lean4/blob/v4.19.0/src/Init/Tactics.lean).
The existing locked support inventory already includes ElabTerm.olean.

Negative evidence now directly asks the kernel to prove `not P` for each
unchanged erroneous proposition P, rather than accepting a compiler diagnostic
about P. The generated statement is parenthesized and fixed by structural tests.
Every negative source must exit zero and print the exact sole named rejection
theorem's permitted axioms. All other outcomes fail closed. This protocol avoids
misclassifying meta-reduction limits as intended proof rejection. It does not
make the still-unexecuted repaired proof text a theorem: fresh exact-head CI and
independent review remain required.
