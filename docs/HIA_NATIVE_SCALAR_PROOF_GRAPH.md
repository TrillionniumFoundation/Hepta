# Native scalar proof graph

The `multiversion_proof_graph` HIA module selects an actual public function
from Core JSON, checks the primitive scalar proof profile, orders its blocks,
and emits the original typed `HIABVP01` graph. It does not establish totality
or equivalence. The native proof owner must first run fresh structural Core
admission, then run the solver and independently replay any counterexample.

## Input and output

The entry has the six-word span ABI: input bytes and extent, mutable output
and extent, mutable work and extent. The source byte limit is 8 MiB. Supply
4 MiB output scratch and 32 MiB work for the whole admitted JSON domain;
the final graph can be smaller than the JSON duplicate-key preflight scratch.

The output's first word selects an original function-array index.
`UINT64_MAX` infers the function only when the document has exactly one.
`UINT64_MAX-1` selects a name whose byte length occupies output word 1 and
whose exact UTF-8 bytes begin at byte 16. Selection must resolve to an actual
public export. No selector carries an admitted or proved flag.

On success the return value is the graph byte count. Work words at bytes
40, 48 and 56 hold the selected original index, the decoded name's work
offset, and the name length. The name remains in the work view. Refusal
values are at least 4294967292.

Work words at bytes 64 and 72 identify the exact signature vector and its
word count. Each parameter type followed by each return type occupies one
eight-byte word: bool=1, unit=2, u8=3, u16=4, u32=5, u64=6, i8=7, i16=8,
i32=9, i64=10, usize=11 and isize=12. The graph itself preserves the
original bit-vector encoding; this additional metadata preserves exact
source-type equality, including usize versus u64 and isize versus i64.
Consumers must compare these exact signature words before translation
validation. The vector remains in the work view and is disjoint from the
returned name.

## Preserved proof profile

Core v1 through v7, primitive unit, Boolean and signed/unsigned integer
scalars, the original supported scalar operation set, and trap effects are
admitted by this graph stage. Calls, resources and floating-point values
remain outside this primitive profile. Limits match the original general
scalar profile: 128 blocks, 2048 operations, 32 parameters and 16 returns.
Acyclic ordering retains the original sorted initial queue and FIFO successor
order, including duplicate branch successors.

This is distinct from the existing bounded native Boolean fast solver.
The graph stage neither expands that solver's capacities nor treats its
resource refusal as a successful proof.

## Evidence

The accompanying qualification record pins the emitted HIA source, native
flat image and the actual assembly, projector and independent seed backend.
477 source cases and 2864 selection/format controls matched the original
independent graph serializer byte for byte. Checks include the complete
general-profile boundary counts, signed and unsigned types, checked
operations, casts, branches, phi arguments, specialization candidates and
multiple public exports. The returned name and selected index were checked
against the original document on every successful call. The exact signature
vector was also compared to the original parameter and return types in all
2864 successful controls.

31 refusal controls cover selection, schema, operations, function shape,
cycles, malformed input and the source-byte boundary. An unreachable-cycle
fixture deliberately bypasses the old structural verifier because that
verifier already rejects unreachable blocks; it is not described as an
admitted source.

Construction used the qualified native assembly and projector roots and
the independent word seed backend, with an empty PATH. Python authored
the source and ran independent development comparisons; it is not a runtime
dependency of this module. Earlier failed development fixtures and build
reports remain external evidence until final closeout.

The complete native scalar proof service and multiversion runtime are
still separate integration obligations. This component record confers
neither execution authority nor a whole-runtime qualification.
