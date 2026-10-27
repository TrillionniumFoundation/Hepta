# HIA P1/P2 checked owned-source native bridge

This code **reuses**, not replaces, the existing Hepta frontend, canonical
semantic snapshots, independent Resource IR checker, executable HIA Core,
and direct LLVM emitter. \`hepta.hia_source_bridge.lower_checked_owned_hia\`
binds actual checked Hepta AST to the project's exact identity and rejects
foreign, raw, unsafe and volatile obligations; it independently verifies
the source-derived owner graph and the executable HIA Program. The Resource
IR graph has deliberately **abstract scalar values**, so it is NOT used as
a substitute for executable numerical SSA, and no compiler refinement is
claimed.

\`build_checked_owned_hia_native(..., rustc=..., clang=...)\` reuses the
same no-replace publication and backend receipt logic as the scalar source
path, but first requires the actual pinned-rustc native source check and a
fresh project identity. The owned Core is independently reverified before
LLVM, native output must bind the same Core and IR identities, and the source
graph is rechecked before/after publication. No silent LLVM/Rust/C fallback.

Current admitted subset: only sources accepted by BOTH the existing
\`hepta.resource_lowering\` and \`hepta.hia_program_source.lower_program\`
closed profiles. It is more limited than either independently; unsupported
generics, foreign pointers, stored loans and runtime capabilities fail
rather than acquiring an unsafe success certificate.

Exact checkout validation (not a claim that they already ran):

\`\`\`sh
python -m unittest tests.test_hia_owned_source_bridge tests.test_hia_source_bridge \
    tests.test_hia_program_source tests.test_resource_ir -v
python tools/release_check.py
\`\`\`

A successful native receipt does NOT prove general provenance, source→Core
semantic equivalence, Core→LLVM refinement, allocator/external correctness,
target execution or whole-language Rust-like safety. Original P0–P7 broad
blockers and physical hardware/model workloads remain open:
\`whole_project_blockers_closed=false\`.
