# General Core function lowering: static work in progress

This branch preserves an unexecuted authoring candidate for moving the complete
`_Function` policy in `hepta.hia_program_native` into HIA. It does not provide an
executable native owner yet. No generated HIA, runtime adapter, selector, build
manifest, installed resources, source-bound cold run, or product result exists for
this candidate. The ordinary product entry remains unchanged.

## Exact source and proposed boundary

The independent base is commit
`608157e52b0b94e0d294f6b99c4e809869f183aa`, tree
`e7c29a60796a1a78946a2c667aa80df86529e532`.
The complete original 47,839-byte module is retained at
`tests/fixtures/hia_program_native_608.py.txt` as the independent oracle.

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

There has been no Python syntax check, IR generation, HIA generation, Core VM
execution, native compilation, component test, caller test, or cold/full
qualification on this candidate. All such steps are pending. See the adjacent
custody and recovered boundary records for the exact limits of this checkpoint.
