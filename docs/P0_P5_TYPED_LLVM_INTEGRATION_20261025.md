# P0–P5 exact typed-u32 SSA/LLVM integration (2026-10-25)

Target source parent: PR #103 `ecfcf53c3c6b1020b12bc1f3349804796672dd8c`.
Upstream typed-u32 backend source: PR #102 `843c0210a2bc617e1bee855c0b67cad16a59e308`, based on `f637901935b6b5c78afebcab229dac90dda1c2cb`.
Before integration, each of six changed paths was verified to have an identical
Git blob at source PR #102's base and at target PR #103's HEAD.
Those six files are transplanted as unchanged original Git blobs:

- `docs/P5_LLVM_SSA_COMMAND_20261025.md` — `89f369298aa1ca9e1ce340855036c1c04b955dff`
- `hepta/llvm_ssa_backend.py` — `bc867822ccea0941cc1494bbe7afa9352d1cd22d`
- `hepta/llvm_ssa_pipeline.py` — `f317205aca3f00a92352d978a043b95add0b362c`
- `hepta/llvm_ssa_target.py` — `c10e8bc35b6969e844ee25bd539bc3812b239034`
- `tests/test_llvm_ssa_backend.py` — `0826166458ffc7ff611e52f056d1e48017b640b5`
- `tests/test_llvm_ssa_integration.py` — `d438d3053bd905473647a3fdca5bbeb9edfe12d2`

The canonical Hepta source semantic encoder and the existing shared Clang
C/C++ strict scalar lowerer remain unique and unchanged. This integration
preserves the signed i32 LLVM SSA path while incorporating upstream PR #102's
homogeneous u32 path, unsigned checked arithmetic and predicates, as well
as its targeted native-source/SSA tests. Mixed/unsupported types reject.

The upstream author independently ran real Clang unsigned arithmetic/abort
primitives, not the complete integrated Hepta-to-LLVM compiler qualification.
This newly integrated HEAD has not passed the full pinned Rust/backend suite
in the local container; no semantic/refinement or hardware claim is made.
General Owner/Loan/Drop/Provenance proof, C/C++ L2/L3, cross-platform
bidirectional ABI, physical boards/GPU, real Agent model A/B, and production
performance are open. `whole_project_blockers_closed=false`.
