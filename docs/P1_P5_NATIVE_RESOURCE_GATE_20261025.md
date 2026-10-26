# P1/P5 source-bound Resource IR gate for native LLVM

2026-10-25. Based on PR #121 SHA b236d424ef8b155812cb014e20217403a2d28d3f.
Candidate: agent/hepta-p1-resource-cert-native-20261025-2252.
This is NOT a declaration of P1 or whole-project blocker closure.

## Problem and fix

The native source pipeline required an actual Rust reference, unique canonical
Hepta checked-source HSIR, source-origin scalar CFG/SSA, and a restricted LLVM
native emitter. Independent Resource IR ownership/borrow/drop checking existed
only as a separate analyzer, not as a mandatory pre-codegen condition.

The new hepta/native_resource_gate.py reuses the ONLY existing semantic
producer, Resource IR lowering, independent Resource IR verifier, and source
origin checker. It introduces no parallel ownership model.

Before LLVM emission, the source pipeline now:
1. Re-derives actual scalar HSIR, CFG and canonical SSA from the checked AST.
   It compares complete wire text and exact hashes, not only function names.
2. Lowers the very same checked program into Resource IR and independently
   verifies the entire abstract resource graph and project/source identity.
3. Requires exact matching function inventory across Resource IR, scalar HSIR
   and SSA; no owned resource type, foreign obligation or unsupported effect.
4. Rejects any forged proof elevation for source-to-IR refinement,
   native Resource IR code generation or whole-language soundness.
5. Validates the Resource IR receipt schema, exact CFG/SSA/source identities
   and real boolean claims at the native source pipeline boundary.
6. Records the independently checked Resource IR digest in native build reports
   and never falls back to ordinary LLVM if this gate rejects.

The admitted native LLVM profile is deliberately copy-only i32/u32 scalar
code with checked panic behavior; full ownership and pointers require a
future IR/codegen profile and cannot be smuggled through this one.

## Truthful semantic scope

The Resource IR abstracts scalar values and tracks only its explicitly
modeled loan/owner transitions. Its source-bound identity is NOT a formal
source-to-IR refinement theorem. It neither models pointer provenance nor
proves machine-code semantics, allocator behavior, C++ foreign code safety,
general Rust lifetime equivalence, or full-language soundness. The
native_codegen_uses_resource_ir claim remains FALSE: it is a mandatory
pre-codegen verification gate, NOT a code-generation IR for LLVM. The legacy
low-level LLVM compilation helpers remain explicitly unqualified.

## Regression files

- tests/test_native_resource_gate.py tests accepted source i32 loop/u32 scalar,
  source/SSA replacement, owned-feature rejection, forged Resource IR claims,
  and mandatory native rejection before any compiler/artifact publication.
- tests/test_llvm_ssa_cli.py repairs previously stale native compiler mocks
  so digest/proof-scope negative tests attack the actual new SSA/CFG protocol;
  source command tests check Resource IR digest and gate status.

Run locally on an exact checkout:

    python -m unittest tests.test_native_resource_gate tests.test_resource_source_origin -v
    python -m unittest tests.test_llvm_ssa_cli tests.test_llvm_ssa_integration -v
    python -m unittest tests.test_resource_ir tests.test_resource_ir_cli -v
    python -m unittest discover -s tests -v

The complete integrated source and pinned rustc are not present in the current
container session, so full repository native tests HAVE NOT RUN here. This
change has been committed to GitHub but is not yet production qualified.
No CI status is a prerequisite for continuing work.

## Remaining blockers

P0 historical HSIR branch reconciliation, P1 general owned aggregates and
Borrow/Drop/Provenance refinement, P2 independent Rust compiler, P3 complete
C migration and pointer safety, P4 C++ RAII/STL/MSVC, P5 production native
backend refinement and representative performance, P6 actual agent trials and
multi-file crash recovery, P7 physical hardware/GPU safety and long-running
qualification remain open or partial.

Do not set whole_project_blockers_closed=true.
