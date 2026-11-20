# HIA static resource ownership

`examples/hia_bootstrap/static_budget.hepta` owns the existing static budget
analyzer's stable graph order, cycle admission, exact resource arithmetic,
synchronous call depth, reviewed v7/v8 resource profile and ordered numerical
policy decisions. Explicit selection is through
`HEPTA_HIA_STATIC_BUDGET_MANIFEST`.

The sole Core verifier, immutable document observation, primitive schema
admission, policy shape/type validation, optional independent heap analysis,
final JSON/report hashing and foreign buffer lifetime remain hosted. This is
not whole-product native replacement, a proof of native runtime costs or a
new proof authority. Existing report schemas, hashes, refusal messages and
claimed quantities retain their original meanings.

## Preserved semantics

The HIA owner implements the original Kahn traversal: the initial ready set
is sorted once; newly ready successors enter a FIFO in sorted successor order.
It does not replace that rule with a priority queue. Unknown graph sources or
targets precede cycle rejection. Duplicated names, missing source entries,
empty graphs and the corresponding original private-helper outcomes are
covered independently against the frozen original.

Every verified definition participates in the call graph. Both CFG branches
are retained, duplicate edges are eliminated and whole-function CFG cycles
refuse static event qualification. The narrower synchronous-frame profile
continues to admit CFG loops while refusing recursive call graphs. An operation
and a terminator each contribute their original VM ticks; every invocation
adds its original additional tick. All allocator opcodes, including null/zero
owner drops, keep their original conservative interaction counts. Call effects
are added for every syntactic call, and each metric takes its own conservative
maximum across successor paths.

The v7/v8 reviewed resource profile is also evaluated in HIA. It compares the
schema and then retains the original function/block/instruction traversal and
first refusal: terminator, opcode and finally the complete function's declared
types. A type refusal in an earlier function precedes an opcode refusal in a
later function. Chain types/operations remain allowed only for the independently
reviewed synchronous-frame profile, not the byte-only static event profile.
The table is the exact existing inventory, including uncalled private code.

Policy comparison preserves function declaration order and, within a function,
allocator interactions, VM ticks and call depth. Requested heap-policy decisions
retain their earlier precedence over these event limits; their measured bounds
still come from the existing independent heap analyzer.

## Exact integer and original structural bounds

There is no u64 truncation, saturation or refusal of admitted large resource
counts. Little-endian variable-width magnitudes carry addition, maximum and
comparison in HIA. A 1,024-function expanding-call program produces a 1,026-bit
VM tick bound and remains admitted when the original policy permits it.

The existing Core domain is unchanged: at most 1,024 functions, 4,096 blocks
per function and 262,144 structural nodes. A conservative whole-program event
magnitude is below `(262144 + 2) ** (1024 + 1)`, hence below 19,475 bits. The
native transport's 4,096-byte magnitude capacity exceeds that complete domain.
Actual buffers use only the observed child magnitude width plus eight bytes;
this headroom exceeds the sum of every possible local event and call in the
original finite node domain. Policy integers are compared at their actual
width and do not inherit that event-magnitude capacity.

Only callee fact bindings named by the current function's operation metadata
are transported. HIA determines which opcodes are calls, performs name lookup,
and computes all counts. This avoids repeatedly transporting and sorting all
previously analyzed unrelated functions on a deep chain. It does not remove a
call edge, change a bound or classify a policy on the host.

## Construction and installed custody

`tools/build_hia_static_budget.py` requires one matching-source cold report or
an explicit development compiler. It captures the HIA source, generation
inputs, existing adapter, frozen original and compiler bytes; validates actual
compiler output and the full packing receipt; and reads captured inputs back.
The manifest schema is `hepta.hia.static-budget-native.v1`.

The source is explicitly packaged through `MANIFEST.in` and the original
native resource inventory. The helper registry supports the same native image
inside an administrator-pinned helper scope. Invalid or empty explicit
selection refuses without calling an old owner. Removing the selector retains
the original default behavior and avoids the optional adapter import.

## Qualification

`tests/test_hia_static_budget_native.py` keeps an independent frozen original
from exact `ad352eeb77d804c14d7407713e23d37e7f037cf1` in
`static_budget_ad352ee.py.txt` under `tests/fixtures/`. Its source controls cover
regeneration, the unchanged compiler profile and independent VM execution.
Native controls compare all source/output/workspace bytes, use exact original
1,024-function and 4,096-block boundaries, forbid all five old semantic owners,
check ordered profile/policy refusal, and run a real wheel from an unrelated
working directory with packaged-source mutation refusal. Pinned helper-scope
controls exercise actual calls, source/manifest drift and selection restoration.

`tools/qualify_hia_static_budget_callers.py` executes seven complete original
test modules, with 77 existing methods and no filtered method or skipped test.
It records exact planned/started/stopped IDs, all five native mode call counts,
image identity and source/input readback. Core verification and heap analysis
continue to run through their existing public implementations.

The native class accepts the explicit `HEPTA_HIA_STATIC_BUDGET_COLD_REPORT`
or `HEPTA_HIA_STATIC_BUDGET_DEVELOPMENT_COMPILER` authority, never both. An
optional `HEPTA_HIA_STATIC_BUDGET_EVIDENCE` directory retains the actual build
and compiler custody for the unchanged full-regression runner. Development
observations are not matching-current-cold qualification; all existing cold,
caller, full-regression and cutover gates remain separate requirements.
