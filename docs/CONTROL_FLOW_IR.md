# Hepta P1: Structural Control-Flow IR (HMIR CFG v0)

This document describes an **implemented experimental snapshot**, not the final
HMIR required by the P1 roadmap or an executable backend input.

## How to use it

```bash
python -m unittest tests.test_control_flow_ir -v
python -m hepta.control_flow_ir examples/results.hepta --frontend-only
# Native validation is the default; --frontend-only explicitly opts out.
python -m hepta.control_flow_ir examples/ownership.hepta
```

The output format is `hepta.hmir.export.v0` containing
`hepta.hmir.cfg.v0`, tied to the source hash and (when available) the loaded
project graph identity. This command is **not** yet part of the stable Hepta
CLI command family. The ordinary compiler/backend still uses the existing
checked AST. The graph is not consumed for native code generation.

## Implemented scope

- Deterministic block IDs; explicit jump, branch, enum-switch, return and
  `Unit` fallthrough terminators.
- Graphs for `if/else`, exhaustive `match`, `while`, half-open `for`,
  and nested blocks. Only continuing arms connect to joins. Loops contain
  structural backedges and both body and exit paths.
- `for` records a range preheader, a structural loop condition, and an
  increment marker. **These are descriptive records, not executable HMIR
  operations.** They do not specify iteration overflow or lowering.
- Statement-level expression metadata (type, span, kind, literal/operator)
  from the already-checked AST, with nested type-presence checks.
- Syntactic `move`, `read`, `mut`, and `release` sites. These are
  explicitly **not** computed lifetime, alias, provenance, or destruction
  proofs. Function-level declared/inferred effects and foreign assumptions
  are copied from the existing checker.
- Reject missing type evidence, invalid expression value encodings, unknown
  statements, statements after unconditional termination, missing graph
  terminators, unreachable generated blocks, and invalid graph edges.
- External declarations have no fabricated executable body.

The export uses the current frontend checker. It cannot establish that the
checker and the Program supplied by an arbitrary Python caller come from
the same source; the CLI relies on the project loader and the standard
`analyze_project` pipeline for their shared provenance.

## Explicitly not implemented

| Required P1 property | CFG v0 status | Closing criterion |
|---|---|---|
| CFG | **Partial** | The implemented subset's structure is recorded; validate semantic lowering and exceptional/panic control edges |
| SSA | **Not implemented** | Dominance, phi/block arguments, memory SSA and well-typed definitions/use ordering with executable semantics |
| Move / Borrow / Drop | **Syntactic only** | Real place-based loan tracking, reborrows, destructor insertion, unwinding/abort semantics |
| Effect / resource analysis | **Frontend annotations only** | Control-flow-aware summaries, resource evidence and independent checker or refinement |
| Pointer provenance | **Not implemented** | Validity, allocation identity, lifetime and alias rules at safe/unsafe boundaries |
| Translation correctness | **Not proved** | Formal or carefully scoped validated refinement from checked AST to HMIR and to each backend |
| Direct LLVM execution | **Not implemented** | Executable IR semantics, target ABI qualifications, native differential tests |

`claims.ssa_constructed`, `claims.independent_borrow_validation`,
`claims.pointer_provenance_proved`, `claims.automatic_drop_lowering`,
`claims.native_codegen_validated`, and
`claims.translation_correctness_proved` are all `false`.

`frontend_checked=true` indicates only that the original checker accepted
the source. The exporter itself does **not** establish type soundness. The
enclosing export distinguishes `frontend_only` from the native check status.

## Next P1 implementation gates

1. Freeze a small-step model for expressions, normal control flow, traps,
   `panic=abort`, and C/FFI interactions; define a machine-checkable
   correspondence between source AST and the typed CFG.
2. Add SSA or block arguments with dominance verification, memory operations,
   and a place model; reject programs not representable by the selected profile.
3. Lower `move`, `borrow` and `drop` from the checker into explicit typed
   operations and prove resource-state preservation for the selected subset.
4. Verify safe/unsafe pointer provenance and target ABI conditions separately.
5. Compare AST -> Rust and HMIR -> Rust/native at fixed source and toolchain
   identities, with differential tests and deliberate negative controls.
6. Only then permit production optimizers and native backends to consume HMIR.

## Relationship with P0/P2–P7

The P0 release-qualification workflow is not replaced by this test module.
The primary Rust codegen path remains the reference for P2 migration.
Clang migration (P3), C++ bridge (P4), Agent protocol (P5), LLVM (P6) and
self-hosting (P7) must not treat the structural CFG as verified semantics.
All existing production blockers remain open until independently qualified.
