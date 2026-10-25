# Hepta P1: pruned scalar SSA / PHI v0

This stage is a deliberately narrow SSA implementation over already checked
structural CFG, **not** a whole-language HMIR or compiler soundness proof.
Existing native code generation does not consume this SSA.

## Supported

By-value scalar parameters and local bindings, scalar name/literal/binary/
unary/cast expressions, mutable assignments, branch joins, while-loop
backedges, early returns and Unit fallthrough. Operation effects and typed
trees remain preserved, including checked arithmetic and potential aborts.

Algorithm: validate exact CFG edges/dominance, compute backward variable
liveness, place **pruned PHI** nodes using dominance frontiers, rename
definitions and uses in dominator-tree order, and require precisely one
PHI incoming reference per actual predecessor block.

- Versioned schema: hepta.ssa.scalar.v0.
- SHA-256 binds the exact CFG and dominance-analysis inputs.
- CLI: python -m hepta ssa examples/ssa_scalar.hepta
- The same real, pinned Rust reference native gate remains mandatory.
- Reject invalid/malformed/unsupported cases before emitting any result.

## Explicit unsupported boundaries

- for-loop range induction, match payload binding, enum/aggregate SSA;
- raw pointers, borrow, ownership, region and Drop, memory provenance;
- calls, FFI, unsafe, allocation, blocking and external side effects;
- complete evaluation-order/abort refinement and backend equivalence.

SSA is **not** evidence of memory safety or semantic equivalence.
scalar_ssa_subset_constructed=true is paired with explicit false
whole_language_ssa_complete, borrow_drop_proven,
pointer_provenance_proven and native_backend_refinement_proven claims.

## Reproduce on exact source snapshot

    python -m unittest discover -s tests -p test_ssa_scalar.py -v
    python -m hepta ssa examples/ssa_scalar.hepta > /tmp/ssa.json
    python -m hepta check examples/ssa_scalar.hepta

Next: explicit side-effect sequencing/abort edges, range induction, Match
payloads, loan identities, lifetime/region/provenance, and Rust/LLVM
refinement plus independent negative, differential and formal evidence.

Production P01–P12 blockers remain open/partial.
