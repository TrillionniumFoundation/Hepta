# General Core function lowering: development work in progress

This branch holds an unqualified authoring candidate for moving the complete
`_Function` policy in `hepta.hia_program_native` into HIA. It is not integrated
into the ordinary product entry. The first actual authoring run checked the
original 22 methods and five helpers, then generated one literal-pool unit before
the first control unit failed the unchanged Core type verifier. Revision 3
corrects only the internal helper return types and remains unexecuted.
No native compilation, Core VM, component/caller result, installed owner or
matching-source cold qualification exists for this Core candidate.

## Exact source and proposed boundary

The independent base is commit
`608157e52b0b94e0d294f6b99c4e809869f183aa`, tree
`e7c29a60796a1a78946a2c667aa80df86529e532`.
The complete original 47,839-byte module is retained at
the `tests/fixtures` directory, named `hia_program_native_608.py.txt`, as the independent oracle.

The proposed owner is all 22 `_Function` methods and the five helpers
`_reject`, `_words`, `_bounds`, `_normalize`, and `_prologue`.
It includes frame and slot assignment, edge/call staging, register versus slot
selection, all 50 currently supported Core opcode branches, range and allocation
control, chains, block and terminator order, trap emission, and function reports.

The authoring policy is copied from that exact source; a restricted authoring
compiler lowers its control into explicit continuation instructions. The later
generator is intended to render those instructions as HIA. Unsupported syntax
must refuse generation. Runtime must not execute or import this authoring policy,
compiler, or oracle. This is a source-translation design, not a table of
precomputed program outputs.

The original `_Emitter` module policy, verifier, machine-plan provider, wrapper
construction, native Code primitives, ELF writer, linker, filesystem operations,
and arbitrary object effects remain outside this proposed owner. Code state,
encoding, and ELF are independently owned work and are not modified here.

## Intended observation discipline

HIA will choose every control branch and the order of individual primitive
observations: attribute/item binding, calls, iteration, truth and rich comparison,
arithmetic, packing, and writes. Actual Python objects and their foreign hooks
remain observations, including independent `__ne__`, evaluation order, exceptions,
and reentrant effects. A mere Python wrapper around the former lowering decisions
would not satisfy this scope.

A source-bound explicit selector, immutable selection scope, versioned one-shot
continuation protocol, and finite HIA unit split are planned. The existing
compiler limits, 64 KiB frame limit, 16 MiB text limit, original caller
denominators, and 3/5-second product budgets must remain unchanged. No performance,
ABI, lifetime, or foreign-domain equivalence claim is established by this static
checkpoint.

## Custody and execution status

The local executor became unavailable during a write. Its last filesystem
mutation acknowledgement is unknown. These files were recovered from retained
tool-call text and the canonical original module, then saved through Git APIs.
The earlier policy reconstruction matches its observed 21,778-byte size, but its
original local hash is unavailable. It is explicitly not presented as a
byte-verified restoration of that local file.

The current candidate additionally uses the original frozenset kind for
`BYTE_RESOURCES`, and refuses a reducer shape lacking an explicit default.
These are new static edits. The earlier requested source text is retained
separately under `experiments/hia_core_lowering_20261111/static-wip-r1`; no prior observation is relabelled.

The first remote authoring request was never dispatched. The corrected r2
request ran once on the pinned CPython 3.14.4 executable, with the original
180-second guardian. All four new Python files passed syntax checks; the complete
22-method class and five helper ASTs matched the retained oracle. It compiled
28 modes into 1,922 control instructions with at most 510 object slots.
The complete 3,925-leaf base and 3,936-leaf candidate byte/mode inventories
matched before and after the attempt.

Of 32 planned HIA units, the literal pool passed the public Core roundtrip.
The first control unit failed with `E_HIA_TYPE` because a `u32` helper result
was compared to a `u64` literal. The run finished HOLD after 22.007921965 seconds;
the guardian naturally reaped the leader and observed ECHILD without timeout or
live-child killing. The original report and logs are preserved in commit
55e39d6a65ff848ee7596c548ddbf98e391bcbdf under the remote-authoring-r2 terminal
directory. No native compiler or product test ran in that remote request.

Separately, seven earlier pushes to this development branch triggered the old
GitHub workflow. Those runs failed and are not native qualifications. In the
latest run, 43085426169 at exact head 55e39d6, the source job rejected a document
reference and the cold command rejected source-closure drift before writing a
cold report. Its job logs and exact run identities are preserved separately.
Future evidence and unexecuted source checkpoints use `[skip ci]`.

## Static revision 2

The renderer emits HIA control units with 64 finite control instructions per
unit, and a separate HIA-owned typed literal pool. The HIA program chooses
cross-unit handoffs using its own program counter. The bridge decodes only the
versioned literal framing and primitive requests. It binds all 22 original
method signatures to native invocations; the ordinary product selector and
source-bound loader have not yet been added.

The 128-byte request/acknowledgement protocol carries a sequence, phase, mode,
object handles and raw truth/iteration observations. Private state remains HIA
owned. Foreign permission is consumed before the effect; BaseException in a
native step, post-call framing or foreign effect permanently closes the session.
No claim about that protocol is validated by this unexecuted source.

The intended initial domain retains normal module and built-in bindings.
Monkeypatching the five private helpers or the reducer built-ins is not silently
presented as equivalent: helper names always select their HIA implementations,
and sum/max/any generator control is compiled into HIA. Literal object identity,
arbitrary stack/traceback introspection, foreign finalizer timing, recursive
resource exhaustion, and tampering with private registries are also unproven.
Normal public method argument binding, dynamic receiver attributes, independent
rich comparisons, module value observations and actual Code effects remain
explicit compatibility targets. Remaining limits must be reported rather than
removed by an implicit retained-owner fallback.

Source revision 2 also refuses value-context chained comparisons, which are
absent from the current policy, rather than incorrectly normalizing arbitrary
rich comparison results into booleans. Original source and all prior unknown
write records remain unchanged in history.

## Revision 3 type correction

Internal startup, instruction-group and dispatch helpers now return `u64`,
matching the existing word-sized status comparisons. The public lowering and
literal-pool entries still return `u32`. Every defined internal status remains
one of 0, 1, 2, 4 or the unchanged ABI refusal value; the final entry conversion
does not add an admitted status. This is an authoring type correction, not a
change to the verifier, compiler caps, packet, phase sequence or policy IR.
The correction has not been generated or executed. The original failing source
and the first unknown local write remain preserved.
