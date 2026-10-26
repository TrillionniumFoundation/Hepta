# HIA ISA P0–P7 exact-source progress checkpoint — 2026-10-26

This is the **AI-native intelligent assembly** roadmap, not the older repository
P0–P7 numbering. All stages remain OPEN/PARTIAL; this change does not claim a
new backend, source-to-IR proof, Rust superiority, whole-project closure, or
physical hardware/model execution.

## Source authority and integration choice

Base is PR #166 merge head `3ed1631b1110d88cc71b484dfa8f7f79d9aa01c3`,
which includes PR #165's Resource IR v5 blobs as a true merge parent. Do not
create a competing IR authority or merge the donor PR separately.

A single source checker and the existing checked `semantic_ir`/HSIR pipeline
remain authoritative. HIA scalar Core v0 is source-replayed; verified Resource
IR is currently a separate abstract resource checker. LLVM's concrete Drop
helper uses the independently verified source-derived Resource IR **type
inventory**, but not executable resource-value SSA. No change here upgrades
those limits.

### Increment actually implemented by this change

- P0: the historical HSIR v0 collision auditor only accepts exact known
  producer field inventories, and rejects rehashed unknown fields and unknown
  proof-claim keys, including a forged `false` future-proof claim.
- P1/P2 boundary: finite concrete Owned LLVM Drop planning additionally
  validates the *root and every reachable child* type identity and descriptor
  shape. It refuses downgraded Buffer types, spoofed scalar names, malformed
  nominal instantiations, and injected aggregate metadata. This remains
  defense in depth; the full checked-source resource gate stays mandatory.
- The new regression fixtures deliberately include rehashed schemas and
  forged native resource type tables. These additions do not themselves
  establish source-to-Core semantic refinement.

## Acceptance matrix (the user's intelligent-assembly stage numbering)

| Phase | Deliverable / current disposition | Required closure evidence |
| --- | --- | --- |
| P0 | HSIR/HIA single authority — PARTIAL | Versioned canonical full representation, all legacy producers losslessly mapped or rejected, exact-head source/native replay |
| P1 | Executable Owner/Loan/Drop/Memory SSA — OPEN | Same typed value/resource CFG, cross-block loans, error edges, provenance, alias and all adversarial negative tests |
| P2 | HIA Core → LLVM — PARTIAL | Owned LLVM consumes only the verified executable Core; actual Rust/LLVM differential with fault/allocator cleanup |
| P3 | c2hia — PARTIAL foundations | Full real-project compile DB/translation unit/ABI inventory; categorized L0–L3 conversions and independent correct-output replay |
| P4 | cpp2hia — PARTIAL foundations | GCC/Clang/MSVC-specific class/virtual/RAII/exception/template cases, rejected unsupported coverage, differential runtime |
| P5 | CPU/GPU optimization — PARTIAL CPU / GPU OPEN | Equivalent Rust/C++ source, same compilers/flags/hardware, finite correctness and memory, CPU/RSS/p95/p99; actual GPU execution |
| P6 | Agent-native edit protocol — PARTIAL | True provider/model A/B, same tool budget, immutable project transaction, token/time/cost/success/correction counts |
| P7 | Hardware & production — PARTIAL emulator / physical OPEN | Physical target MMIO/DMA/IRQ coherence, recovery/failure injection and sustained service/runtime metrics |

## Reproduction commands on a **full checkout** of this commit

```sh
python -m unittest tests.test_hsir_wire_audit tests.test_owned_drop_plan -v
python -m unittest tests.test_owned_drop_llvm tests.test_resource_views tests.test_hia_core tests.test_hia_oracle -v
python -m unittest tests.test_native_resource_gate tests.test_llvm_ssa_cli tests.test_llvm_ssa_origin -v
python -m hepta resource-ir examples/resource_views/labelled_view.hepta
python tools/release_check.py
```

Only tests actually executed on the exact resulting source SHA may count as
exact-head qualification. Remote CI queue or not-run status is not an
engineering stop, but cannot be upgraded to `passed`. Full native, target,
physical GPU, real Agent/model, and formal refinement acceptance remain OPEN.
`whole_project_blockers_closed=false`.
