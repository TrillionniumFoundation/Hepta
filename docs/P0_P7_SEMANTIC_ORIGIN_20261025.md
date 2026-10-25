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
