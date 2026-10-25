# P0/P1 semantic authority integration — bounded stacked pilot

## Frozen source identities

- Integration base: PR #14, 66b3359d384e4cf4496ca40bf499994575ffd3ca.
- Imported algorithms: PR #37, af3f406f4d980ae2e8c5fca23b4ed12bee5195af.
- Competing implementation: PR #36, 0dbae1504ad6acf1939fe02c6934a3435bb16d25.
- All P0–P7 and P01–P12 completion gates remain **OPEN/PARTIAL**.

## Sole canonical authority, restricted compatibility

hepta.semantic_ir.lower_checked_program is the sole source semantic encoder.
hepta.hsir is NOT an independent second encoder from PR #36. It converts a
checked, digest-bound PR #14 snapshot to PR #37 CFG/SSA's expected structure.
The derived digest binds source_semantic_sha256 and source_sha256.

The conversion fails closed on any untyped expression, unknown node/type,
generic/lifetime/owned parameter, borrowed return, import, nominal struct/enum,
unsafe/FFI/volatile external obligations or unsupported statement/expression.
The downstream SSA imposes additional restrictions (for example, no range
induction). It does not implement general ownership-aware SSA.

Only the four PR #37 analysis modules are copied as exact existing Git blobs;
no independent native compiler backend or alternate parser is imported.
The tests include a source-to-scalar-SSA/independent-verifier path, native
source-checker gating, deterministic identity and deliberately corrupted
canonical snapshots. Passing those tests is not source-to-native refinement
proof, Rust safety parity or ABI production qualification.

## Reproduce

Run in a full checkout of this exact integration branch:

    python -m unittest tests.test_hsir_bridge tests.test_cfg_analysis tests.test_ssa_scalar tests.test_ssa_verify -v
    python tools/release_check.py

The first command qualifies a bounded P1 analysis subset only. Full exact-head
qualification and review remain required before merging; runtime codegen and
the rest of P0–P7 stay open.

## Next blockers

1. Define a verified canonical cross-module ownership/effect/resource SSA.
2. Reconcile CLI and executable lowering; prove/bound AST→IR and IR→native.
3. Rebase C/C++ migration, ABI, Agent and LLVM paths onto one complete
   checked graph without promoting unverified foreign assumptions.
4. Run independent real-host/physical target, long-run performance and
   real-model Agent evaluations.

Keep whole_project_blockers_closed=false.
