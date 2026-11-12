# Bounded-read r3: preserve the callable rejection continuation

Status: **static source work in progress, unparsed and unexecuted**. No public
entry, contract, wheel resource, global workflow, or qualification result was
changed. The exact acffa base and the prior r1/r2 candidates remain preserved.

HIA now emits the original unprefixed reason and requests the currently bound
foreign `_reject` callable. A normal pre-read helper return resumes the original
`stream.read(limit + 1)`; a normal post-read helper return yields the original
payload. The helper return value is discarded inside the effect, before another
HIA transition or foreign read binding. Protocol magic is HIARDB02 and the
candidate manifest schema is `hepta.hia.bounded-read-native.v2`.

This revision deliberately retains the callable itself, including the default
prefix and diagnostic construction. It does not specialize a function based on
identity or `__code__`, and it does not claim this residual has been migrated.
The r2 finish permission guard remains. General module-global fallback,
foreign finalizer lifetime, context/exception parity and actual filesystem
behavior remain unproved.

`controls/run_reject_continuations.py` is new, unparsed control source for
twelve fixed cases. It requires a real source-bound native image, compiles the
original complete acffa function/class/helper AST as the oracle and compares
ordered effects, return identity and exception graphs. It does not replace
the original eight tests, the ten planned private terminal controls, original
3/5-second assertions, or any full/cold gate.

The adjacent source-authoring draft has a 4025-member manifest: all 4023 exact
base leaves plus the two new candidate source files. Its fixed worker generates
and roundtrips public Core with all original caps, keeps source bytes unchanged
and stores derived output separately. It additionally resolves source/evidence
paths before checking containment and reapplies the fixed manifest bound on
the final read. No outer controller, runtime input freeze, dispatch request,
workflow or trigger exists for this draft. Required future owner limits remain
180 seconds plus 3 seconds cleanup, and 60 seconds for the authoring child.

This checkpoint interrupts authoring to prioritize diagnosis of the original
ELF 51-caller CI failures. No test or image result is asserted here.
