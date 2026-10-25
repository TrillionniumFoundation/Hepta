# P1 versioned HSIR v1 to CFG / scalar SSA verified adapter

This change is stacked on the exact PR #37 source at
af3f406f4d980ae2e8c5fca23b4ed12bee5195af. It does not change the default
LLVM backend or authorize unverified memory/resource semantics.

## Implemented flow

Use the new CLI form on a source already accepted by PR #37 scalar CFG/SSA:

    python -m hepta ssa-v1-verify examples/ssa_scalar.hepta --rustc /path/to/rustc

The CLI enforces the existing native Rust reference gate before lowering.
For the special v1 command, it creates the *existing* PR #36 producer's
hepta.hsir.v0 signed-content snapshot, passes it to the shared
hepta.hsir.integration.v1 envelope implementation, independently revalidates
the v1 envelope and embedded v0 producer, then reconstructs the exact
HSIRSnapshot expected by the existing CFG builder.

The CFG, scalar SSA and independent SSA verifier run in their original modules.
The result binds all provenance edges: v1 SHA -> v0 SHA -> CFG SHA -> SSA SHA
-> verification SHA. A missing/mismatched edge rejects; unsupported
constructs reject using the pre-existing CFG/SSA profile rules. The result is
hepta.ssa.integration.v1, containing these structures and the original proof
flags. It explicitly sets source-to-IR semantics, memory safety,
native codegen and foreign contract proofs to false. The final output's
reference_validation is CLI metadata added after its snapshot SHA; its
unbound nature must not be hidden from consumers.

A PR #14 source_bound_v0 payload is **not** compatible with PR #36's frozen
structural-expression format. The new adapter explicitly rejects that profile
with E_V1_SSA_UNSUPPORTED_PRODUCER. A genuine checked translator must be
developed and tested before these sources can be combined in LLVM lowering.
The shared v1 envelope has identical Git blob bytes in PR #53 and this branch
to reduce future semantic authority duplication.

## Validation scope

Isolated local Python tests: 14 producer-envelope tests and 3 mocked
consumer-wiring tests passed. The mocked CFG/SSA tests are not a validation
of real compiler source lowering. Another 5 real frontend/CFG/SSA integration
tests are committed in tests/test_hsir_v1_ssa.py, comparing the new flow to
the old native-checked source pipeline, exercising branch/loop PHI checks,
identity, and incompatible producer rejection; these tests have NOT been run
here because a complete branch checkout and pinned rustc are unavailable.

### Remaining P1 and production conditions

- Real PR #37 producer/CFG/SSA tests must execute against this exact branch.
- PR #14 must gain independently checked expression/owner/lifetime/provenance
  representation before direct consumption by PR #37 can be accepted.
- Formal source-to-IR/backend refinement remains unproved.
- PR #41 and PR #42 symlink publication fixes remain independent downstream
  patches to integrate before relying on P6 LLVM artifact publication.
- All P0–P7 and original P01–P12 system qualification gates remain open.
