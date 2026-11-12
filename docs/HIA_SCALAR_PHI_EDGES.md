# Scalar LLVM PHI edge checks

`hia_scalar_lowering_check.py` verifies one selected, acyclic scalar internal
function against the existing Core SMT encoder. Its optional `llvm_text` input
is useful for auditing the actual lowered instructions. This change repairs
two ways that malformed LLVM could pass that selected-body check. It does not
change the Core interpreter, emitter, public ABI or native execution authority.

## Reproduced failures

On the runtime source `b47ce924c5941b42448e9da0b07a2bcedaf75d1f`, a two-PHI
join can return the wrapping sum computed by its predecessor. The emitted
instructions are valid:

```llvm
%p_1_0 = phi i32 [ %t1, %edge_0 ]
%p_1_1 = phi i32 [ %t1, %edge_0 ]
```

Changing the second incoming value to `%p_1_0` makes the module invalid:
that value is defined in the destination block, and cannot be read on the
incoming edge from `%edge_0`. The old symbolic interpreter immediately bound
the first PHI, then read that new binding for the second. It reported
`verified`, value/abort equivalence and unreachable poison. Actual LLVM 20
`opt -passes=verify -disable-output` rejected the same bytes because the
instruction does not dominate its use. The unmodified emitted bytes passed.

A second mutation changes the predecessor's jump into two branch edges to the
same PHI block while retaining only one incoming entry. The old checker reduced
predecessors to a set of block names and accepted the missing edge. LLVM 20
rejected it. These observations concern the supplied mutation input; they do
not show that the production emitter generated either malformed module.

The regression-only commit `50a2c11ce9f7895736bd1a77d79ab9b3d327b68c`
preserves the old implementation plus the new tests. The protocol-v2 observation of
that commit found three malformed variants incorrectly accepted: an earlier
PHI dependency, that dependency on a constant-false branch, and the duplicate
CFG-edge case. All four legal fixture variants compiled and agreed with the
Core interpreter and independent arithmetic expectations on 384 native calls.
The [retained evidence](https://github.com/TrillionniumFoundation/Hepta/blob/06b1e9b284f612c47a2205e79c8685d8b366d9de/experiments/hia_scalar_phi_edges_20261105/README.md)
also preserves protocol v1 and explains why its constant-branch case was
semantically `refuted`, rather than an additional `verified` failure.

## Repaired checks

The checker records the defining block of each SSA value, retaining the existing
global uniqueness check. It obtains a topological order from the existing
acyclic-CFG check and calculates dominators using bounded integer bit sets.
Every PHI incoming operand must exist, and its definition must dominate that
specific predecessor edge. This structural check examines all incoming
options before symbolic execution, including branches with constant conditions.

Incoming entries are compared with the full CFG predecessor-edge inventory.
The existing selected profile supports one entry per predecessor; parallel
edges into PHI blocks are refused instead of silently collapsed. This change
does not extend the profile to cyclic PHIs or general LLVM syntax.

Symbolic execution reads every PHI right-hand side from the predecessor
environment, then installs all outputs together. PHI declaration order cannot
make a destination-block value available on its own incoming edge. Existing
instruction/path limits, shared callee budgets, deadline checks, type checks,
poison checks and the mandatory fresh SMT query remain in place. The static
CFG check also bounds the block count by the existing instruction allowance.

## Validation scope

`tests/test_hia_scalar_phi_edges.py` exercises legitimate one- and two-predecessor
joins in both PHI orders; earlier, later and self-PHI references; a value from the
other predecessor; undefined and mistyped inputs; omitted or duplicate incoming
entries; parallel CFG edges; and misplaced PHIs. A negative control forbids any
symbolic value evaluation until all incoming dominance checks have completed.
Another control checks that the all-export sequential proof consumer cannot
inherit a successful result from the malformed lowering.

Independent LLVM verification and finite native calls complement the tests.
They do not prove the Python parser or SMT encoder correct for every program.
The existing limitations remain: no general Safe Core soundness theorem,
ownership/resource theorem, full LLVM validation, machine-code refinement,
C ABI proof, concurrency/hardware result, or execution/publication authority.
Any unified composition qualification must bind the repaired source again.
