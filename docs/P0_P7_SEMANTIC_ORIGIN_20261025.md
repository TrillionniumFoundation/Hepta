# P0–P7 execution checkpoint — semantic authority and strict native origin

Date: 2026-10-25. This is an incremental, stacked candidate, **not** a 1.0 release,
complete P0–P7 qualification or a merge of all parallel PRs.

## Source basis and unique compiler authority

- Base: PR #107 exact head 51287478afcab344e210580f162f59e353b2abd9.
- Own branch: agent/hepta-p0-p7-llvm-provenance-20261025.
- Sole checked-source semantic encoder: hepta.semantic_ir.lower_checked_program,
  canonical wire schema hepta.hsir.v0.
- hepta.hsir is a derived **scalar compatibility adapter**, distinct
  hepta.hsir.scalar.v1 schema, never a competing canonical source.
- hepta.hmir and hepta.resource_ir remain limited and independently validated
  representations; neither is promoted to full-language soundness.
- No parallel PR tree is automatically merged. Incompatible old HSIR v0
  envelopes remain incompatible and must be explicitly rejected.

## Code delivered on this candidate

**P0: semantic source rederivation.** The strict source LLVM build invokes the
one canonical producer again against the exact checked program, derives the
reviewed scalar compatibility view, and compares the complete snapshots. A
rehashed, structurally valid but different scalar program cannot present
itself as the projection of the checked source. The receipt records canonical
semantic and derived scalar identities. This is source identity checking, not
a proof that the sole encoder has correct semantics.

**P3/P5: native LLVM instruction containment, verified SSA/CFG origin and target object symbols.** Both
native host and cross-object compilation entrypoints require a bounded, exact
finite LLVM vocabulary for the reviewed i32/u32 scalar SSA generator.
Arbitrary rehashed loads/stores, globals, foreign calls, inline asm, unknown
declarations, malformed CFG labels and excess instructions reject before Clang.
The strict source compiler now supplies its actual verified SSA and CFG to
both LLVM compilation methods: they independently re-emit LLVM and compare
the complete IR object. A rehashed, grammar-valid wrong-code LLVM program
must fail this strict source build path.

The legacy low-level compiler API remains available for backward compatibility
but explicitly reports ssa_cfg_origin_rechecked=false unless a complete
typed SSA+CFG pair is provided. Supplying only one is an error. The strict
source-build path requires true and records the canonical HSIR, scalar HSIR,
CFG, SSA, verifier and LLVM identities. Target objects are independently inspected for bounded ELF64/COFF/Mach-O64 section and symbol tables: exports must equal the reviewed function inventory and unresolved symbols must be contained in the sole admitted abort external. The parser is reused unchanged from PR #109. This is object identity and import containment, **not** complete ABI or semantic qualification. No origin/grammar receipt proves
value-level semantics or whole-language soundness.

## Executed tests and unclosed scope

Local Python 3.13 / Clang 17 executed **7/7** self-contained tests in
tests/test_llvm_ir_profile_contract.py, including two real Clang native objects (scalar and PHI/backedge),
and rejected hostile LLVM instructions/CFG profiles. The exact test and
validator file bytes matched their uploaded Git blob identities.

The integrated test sources tests/test_llvm_ssa_origin_gate.py and
tests/test_semantic_source_origin.py are committed but **not executed**
on this full repository branch HEAD in this local execution environment;
rustc/Lean/QEMU and physical hardware are unavailable here. A Git commit,
snapshot hash or PR by itself is not evidence of native qualification.

| Stage | New incremental change | Still open |
| --- | --- | --- |
| P0 | Sole canonical source HSIR projection rederived in strict builds | Exact-HEAD whole-project/branch integration, schema consumer qualification |
| P1 | Explicit verified scalar SSA/CFG identity re-emission | General owned ADTs, Borrow/Drop/Provenance, formal refinements |
| P2 | No new Rust compiler work | Rust core parity, checked diagnostics and reproducible native builds |
| P3 | Clang target-object export/import symbol gate integrated; existing C migrator retained | Real multi-TU C pointer/ownership migration with complete inventory and full bidirectional ABI |
| P4 | Existing C++ L1 and bridge retained | RAII, STL/templates, real GCC/Clang/MSVC bidirectional ABI |
| P5 | Closed LLVM grammar, strict source origin and ELF/COFF/Mach-O symbol import/export gate | Integrated native tests, independent value equivalence and performance |
| P6 | Existing Agent protocols retained | Real-model 2x2 comparisons and crash-safe multi-file transactions |
| P7 | No physical hardware expansion | MMIO/DMA/IRQ, real board and GPU qualifications |

Do not set whole_project_blockers_closed=true.

## Reproduce on the exact candidate checkout

    python -m unittest tests.test_llvm_ir_profile_contract tests.test_llvm_ssa_origin_gate tests.test_semantic_source_origin -v
    python -m unittest tests.test_hsir_bridge tests.test_ssa_verify tests.test_ssa_reaching tests.test_llvm_ssa_backend tests.test_llvm_ssa_target tests.test_llvm_ssa_integration -v
    python -m unittest discover -s tests -v

For native suites use the actual pinned toolchain. Preserve exact source hashes,
tool identities, positive and adversarial results, failures, skips and blockers.

Additional new target-object symbol integration tests are committed on this branch but are not included in the 7/7 local self-contained count. PR #109 donated hepta/object_structure.py and hepta/object_symbols.py as unchanged Git blobs, verified against donor blob SHA identities.


## P1 follow-up: exact type/shape and resource source binding

New code on this stacked candidate extends P1 **without** introducing a second
semantic encoder or upgrading any source-refinement proof flag.

- The existing independent scalar SSA verifier now checks typed expression
  origin by canonical JSON equality (which distinguishes integer 0/1 from
  boolean false/true), rather than Python dictionary equality.
- The derived scalar HSIR requires literal bool proof flags and function
  visibility, not integers that Python considers equal to booleans.
- SSA Block, Instruction, Definition, PHI, PHI Edge, Function and top-level
  claims are closed inventories; unknown owner/drop/effect metadata fails
  before entering the native compiler.
- Source CFG predecessor structure is rechecked for every PHI. In particular,
  zero-input PHIs in entry blocks and single-predecessor non-join PHIs reject.
- SSA/CFG intake enforces bounded canonical JSON, no duplicate keys and no
  NaN/Infinity; tampered snapshots cannot be laundered by rehashing.
- LLVM strict origin now regenerates deterministic scalar SSA from the exact
  typed CFG before re-emitting LLVM, so even a structurally accepted
  noncanonical SSA cannot claim native origin.
- The existing resource-lowering owner is preserved. A new
  verify_resource_source_origin re-runs the sole canonical source encoder,
  checks the exact re-lowered Resource IR against the supplied graph with
  canonical type-faithful JSON comparison, validates source/project identities
  and reruns the independent resource verifier. A normal hepta resource-ir
  source export records source_binding_verified=true only after this check.
  Data-only hepta.resource_ir CLI output remains source_binding_verified=false.
  Both continue to declare source_to_ir_refinement_proved=false and
  native_codegen_uses_resource_ir=false.

New regression sources:
- tests/test_ssa_verify.py: forged 0/False and 1/True, signed duplicate JSON
  keys, NaN, invalid entry PHI, unreviewed nested metadata and proof claims;
- tests/test_hsir_bridge.py: forged derived claims and function visibility;
- tests/test_llvm_ssa_origin_gate.py: rehashed noncanonical PHI order;
- tests/test_resource_source_origin.py: rehashed resource source/project
  identity, stale checked source, valid exact-source receipt;
- tests/test_resource_ir_cli.py: source export vs data-only qualification.

**Execution status:** These repository-integrated regression tests are added
but NOT marked passed on this branch until run on one immutable exact HEAD.
The isolated 7/7 locally run LLVM-grammar tests remain valid only for their
exact two unchanged Git file blobs. A new workflow was added for pinned
native origin/resource checks, but a queued workflow is not a pass.

P0/P1 production blockers still include whole-program ownership, borrow/drop
and pointer provenance semantics, full-language and native backend refinement,
a complete Rust compiler core, ABI-qualified C/C++ migration, real Agent
comparisons and physical hardware. No step above proves universal memory
safety or general Rust performance parity.

## Next exact-head commands

    python -m unittest tests.test_hsir_bridge tests.test_ssa_verify tests.test_ssa_scalar tests.test_ssa_reaching -v
    python -m unittest tests.test_llvm_ir_profile_contract tests.test_llvm_ssa_origin_gate tests.test_llvm_ssa_backend tests.test_llvm_ssa_target tests.test_llvm_ssa_integration -v
    python -m unittest tests.test_resource_source_origin tests.test_resource_ir tests.test_resource_ir_cli -v
    python -m unittest discover -s tests -v

The full suite may require other toolchains and platform-specific environments;
retain not-run/unsupported states explicitly. Never promote the temporary
scalar-source origin receipt to a C++ ABI, GPU or formal soundness proof.
