# Core lowering ownership ledger at static source 7d73

This is an intermediate control owner. No execution result exists for source
7d73 at the time of this ledger. The proposed verified builtin domain is the
existing verified Core tree and its normal backend/module bindings; it has not
yet been exercised through the new owner. Neither the bridge nor this ledger
establishes a pure HIA object runtime.

## Control being moved

All 22 original Function methods and five helpers are translated into HIA
control instructions. HIA chooses opcode dispatch, frame/slot policy, receiver
and argument observation order, loops, truth-dependent branches, edge staging,
machine operation sequence, blocks, terminators, rejection calls and returns.
The ordinary entry selector and source-bound loader are still pending.

## Explicit hosted value and effect primitives

| Opcode | Hosted primitive | Native control and remaining boundary |
|---|---|---|
| 1 | Global lookup | HIA names and schedules the lookup; ordinary module/builtin data and Python binding remain hosted. Five default policy helpers resolve to native invocations. |
| 2 | Attribute binding | HIA chooses object/name/order; Python descriptors and __getattribute__ remain foreign. |
| 3 | Attribute store | HIA chooses target/value/order; Python object storage and hooks remain foreign. |
| 4 | Item lookup | HIA chooses key and ordering; builtin/foreign indexing, hashing and equality remain hosted. |
| 5 | Item assignment | HIA chooses the mutation and operands; Python container storage/hooks remain hosted. |
| 6 | Bound call | HIA selects the previously bound callable and evaluated arguments; invocation and foreign exceptions remain hosted. Calls to default Function/helper implementations reenter HIA. Code effects belong to their separate owner. |
| 7 | List/tuple/set/dict packing | HIA selects kind and source operand order; Python object allocation and container primitives remain hosted. |
| 8 | iter | HIA chooses loop entry; actual iterator construction and hooks remain hosted. |
| 9 | next | HIA chooses each iteration and handles completion; Python iterator semantics remain hosted. |
| 10 | Truth observation | HIA chooses the truth point and ensuing branch; Python __bool__/__len__ remain foreign. |
| 11 | Arithmetic/in-place arithmetic | HIA chooses operation and operand evaluation order; Python unbounded values and arithmetic hooks remain hosted. |
| 12 | Unary arithmetic | HIA chooses operation/order; Python value operations remain hosted. |
| 13 | Rich comparison and membership | HIA chooses exact eq/ne/order/in/not-in operation and branch; Python rich results, hashing and containment remain hosted. Independent __ne__ is retained. |
| 14 | Unpacking | HIA chooses arity and assignment order; Python iteration and exact unpack exceptions remain hosted. |
| 15 | Slice construction | HIA chooses the three already evaluated fields; Python slice object remains hosted. |
| 16 | Comprehension append | HIA owns comprehension traversal/filters/value order; exact Python list storage remains hosted. |
| 17 | Register-plan import | HIA chooses the original observation point; VALUE_REGISTERS and import runtime remain hosted. |
| 18 | Raise | HIA selects rejection call and exception value; Python exception delivery remains hosted. |

Scalar/text equality, arithmetic, and ordinary object allocation in this table
are not relabelled as native merely because HIA schedules them. Their future
replacement needs a HIA value/object/text/integer runtime, including exact
Unicode, signed/unbounded integer behavior, alias identity, and relevant
exception delivery. Exact builtin facts can be internalized separately while
preserving explicit foreign observations for user-defined behavior.

## Compatibility targets and open extension boundaries

The initial implementation aims to preserve actual argument objects and stable
aliases; receiver binding before argument evaluation; RHS before assignment
targets; repeat dictionary reads; separate equality and inequality; inplace
updates; mutable iteration; actual exceptions; partial Code mutations; and
one-use foreign permission across normal and BaseException paths. These are
targets for independent differential tests, not proven facts about this source.

The finite translation currently assumes default private helper/reducer
bindings. Monkeypatching those helpers or sum/max/any, identity of newly boxed
literal objects, arbitrary stack inspection, destructor timing, recursive
resource exhaustion, and private registry mutation remain unclosed. Existing
retained code stays available as a separate oracle. There is no silent selected
fallback proposal and no permission to remove the old implementation.

## First validation boundary

The frozen authoring-r2 request keeps 180 seconds and the original source,
function, block, instruction, unique-SSA-name and argument limits. It generates
and publicly verifies every unit, checks all original 22 method and five helper
ASTs, and preserves original/source file inventories. It does not run a native
compiler, Core VM, product suite, cold qualification, or full regression.
Native compilation and original caller coverage remain necessary subsequent
gates; later source-bound cold admission remains separate again.
