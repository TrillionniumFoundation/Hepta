# P0–P7 integrated candidate acceptance ledger (2026-10-25)

This is a **draft candidate**, not a production-safe completed language.
Exact base PR #43: `3937cfd964d5ec3e58ed1f00d5012a547c14b1df`.
The following original Git blob identities, not cherry-pick approximations,
are assembled without overlapping source paths:

- P3 PR #45: `89913e4d4ab9c081ef324425927f4782ce38a6c6`. Windows 8.3 short-path
  audit and safe command-path canonicalization. Real native Windows x86_64
  qualifying receipt exists for exact `52a435e1...` in run 40169040021:
  two optimization levels, 181 ABI calls each, wrong compiled C rejected.
- P4 PR #46: `d8d8b8c6490b3908e930a5ad496307f4b70bf1c5`. Shared C scalar
  lowerer for strict `noexcept int(int...)` C++ L1 candidate migration.
- P5 PR #44: `fcd788008a16298f27f77eeea06b93a7c2e79bc9`. Real
  LLVM checked-scalar SSA PHI codegen, incorporating PR #41 and #42 output-path
  symlink safeguards, mandatory pinned Rust reference gate.
- P6 PR #47: `40e1493acf7dc79076f85b6929d11f8e919a9c01`.
  Read-only pin-consistent Agent semantic inspection API.

Existing PR #14 P0/P1/P2/P3/P4/P6/P7 implementation remains the base.
This branch contains no repeated authoritative language parser or new
C lowering implementation. The sole source semantic encoder is
`hepta.semantic_ir`. The PR #37 CFG/SSA path consumes its fail-closed scalar
projection from PR #43.

| Phase | Scoped state | Still-open production blocker |
|---|---|---|
| P0 | Source provenance and canonical semantic projection; 23 scoped tests passed in run 40168338100 | Whole graph/backend semantic consolidation, exact-head full release requalification and review |
| P1 | CFG, dominance, PHI, independent scalar SSA verifier | General owner/loan/provenance/Effect SSA, source-to-IR/backend refinement proof |
| P2 | PR #14 real C project migrator and declaration inventory retained | More C constructs/configurations and generally sound ownership inference |
| P3 | Actual Windows x86_64 finite native ABI matrix passed on isolated P3 commit | Integrated head and independent Linux/ARM/macOS receipts, broad C++ ABI |
| P4 | PR #14 real C++ L0 library bridge + strict L1 source candidate addition | L2/L3 arbitrary class/RAII/templates/STL source conversion and memory-safety qualification |
| P5 | Additive direct LLVM SSA subset | Exact-head native/ABI/performance tests, general pointers/owners/optimizations |
| P6 | PR #14 v4 crash-consistent Agent workspace + pinned semantic inspection | Multiple real-model/seed equal-budget A/B trials and human correction cost |
| P7 | PR #14 Cortex-M4 QEMU system/IRQ evidence, real Windows ABI | Physical board/DMA/GPU, multi-machine long-term RSS/p99/recovery |

The *integration branch itself* must independently pass the exact-head
full release gates and all applicable targeted tests. An isolated child
run cannot replace that. No claim of production Rust-wide safety or
performance superiority, arbitrary C++ equivalence, physical hardware
qualification or real AI-model productivity is made.

**whole_project_blockers_closed=false**.
