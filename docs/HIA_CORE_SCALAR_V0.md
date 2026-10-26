# HIA scalar Core v0 — executable SSA consumer boundary

> Candidate increment, **not** a declaration of completed P0–P7 or of HIA Core v1.

## Scope and single semantic authority

The only checked-source authority remains hepta.semantic_ir.lower_checked_program
(hepta.hsir.v0). hepta.hsir is a fail-closed scalar adapter, not a
second source semantics authority. hepta.cfg, hepta.ssa,
hepta.ssa_verify, and the independent Resource IR checker/lowerer are reused
unchanged.

The new hepta.hia.scalar-core.v0 wire document packages existing verified
scalar CFG+SSA and a source-bound Resource IR gate receipt under one
canonical digest. The decoded scalar SSA is directly supplied to the existing
emit_scalar_ssa_llvm; no parallel compiler/optimizer is introduced.

The source-facing native pipeline calls
HIAScalarCore.qualified_for(program, checked, project_sha256=...)
before LLVM generation. This replays canonical HSIR, Resource IR validation,
CFG, SSA and verification from the **same checked source AST**, requiring
exact structural equality with the decoded HIA payload. Data-only decode()
does NOT establish source authenticity; self-rehashing cannot qualify a new
program body.

## Wire rules

- Closed schema/status/proof fields, strict SHA-256 digests; reject unknown
  and duplicate keys, nonfinite values and noncanonical JSON.
- 8 MiB serialized document budget, 262,144 structural nodes, 128 maximum
  post-decoding nesting. Source checks and compiler must still be sandboxed.
- Nested CFG and SSA retain their original schema, source identities,
  function inventory and independently verified SSA/PHI relationships.
- Full project digest, canonical and scalar-HSIR digests, Resource IR
  gate and verification identity must remain equal on source replay.
- Existing native Rust reference gate, source preservation, object scanner,
  same-source LLVM regeneration, no-replace publication and final artifact
  verification remain mandatory.

## Deliberately unclosed

This is the original i32/u32 scalar LLVM subset, **not** general executable
ownership-aware HIA v1. It cannot lower executable Owner/Loan/Drop
instructions, pointer provenance, general FFIs or arbitrary C/C++ code.
The abstract Resource IR is an enforced gate and is **not** the native
codegen's executable input. Claims for owned SSA, provenance, whole-language
soundness and backend refinement remain FALSE. The unqualified standalone
LLVM emitter APIs remain separate from source-qualified publication.

The next real P1/P2 milestone is unifying numerical SSA and resource
transitions into one operational, typed control-flow IR, with exact lowering
and verifier obligations, followed by migration of the actual Owned LLVM
emitter to consume that verified IR exclusively.

## Test commands on the exact integrated source checkout

Run targeted tests (requires complete repo and toolchain for native portions):

    python -m unittest tests.test_hia_core tests.test_native_resource_gate tests.test_llvm_ssa_cli tests.test_llvm_ssa_origin -v
    python tools/release_check.py

Acceptance requires real pinned rustc/Clang native and adversarial tests,
not just a passing structural/unit smoke. Unchanged historical-SHA reports
cannot qualify this integration.

whole_project_blockers_closed=false
