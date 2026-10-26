# P3/P5 unified five-target object symbol origin — 2026-10-25

This increment is **stacked** on P0–P6 exact-blob unified PR #135,
base `c483b4cedcc03a8bfcbe02d3c6b3f644f8c8af59`.
The canonical source frontend, HSIR, scalar CFG/SSA verification,
Owned LLVM compiler and 46-gate release runner remain unchanged.

## Integrated exact upstream source

Three files were absent at the starting branch head and were taken as
**unchanged immutable Git blobs** from PR #121 exact head
`b236d424ef8b155812cb014e20217403a2d28d3f`:
- `hepta/object_structure.py` blob
  `5231ee37ef4ca65a3175a1162178ea21b9503082`.
- `hepta/object_symbols.py` blob
  `75c27ba7b446b39633427a344bf32f66838225eb`.
- `tests/test_object_executable_exports.py` blob
  `5ff7ef8506742aaf8468e2876476770682c36a21`.

The existing `hepta.llvm_ssa_target.compile_ssa_target_object` (already
patched on #127 with staged-vs-published inode/byte authentication)
uses the single imported object symbol checker **before** publishing:
- Reject malformed ELF64, COFF, Mach-O 64-bit sections and symbol tables.
- Reject exports whose executable section flags/ranges do not match,
  including function size for ELF and Mach-O code/zerofill distinction.
- Require exactly the source-verified SSA/LLVM named exports.
- Reject all unresolved externs outside the currently modeled `abort`.
- Publish by no-overwrite hard link and keep the existing same-inode,
  byte-for-byte post-publication verification.
- Record `object_structure_qualified`, `object_symbols_qualified`,
  sorted defined/undefined names, and artifact SHA in the unqualified
  cross-object receipt.

The source-facing `hepta.llvm_ssa_pipeline.build_llvm_ssa_source` performs
another **independent parse of the actual staged object bytes** and compares
the native receipt with the strict source SSA/CFG export graph. A rehashed
native receipt or a valid-looking machine header alone cannot upgrade an
unreviewed export/import to a trusted source build.

## Test evidence and scope

The upstream donor PR #121's standalone 5-target real Clang object-mutant
experiments are earlier local evidence, **not qualification of this
integrated source SHA**. The original donor 5-target executable-placement
negative test is retained byte-for-byte, and
`tests/test_llvm_ssa_target.py` now independently validates every produced
target export/import receipt and tests malicious symbol-rejection before
publication.

Executed in this parallel development effort on exact self-contained
source bytes: the separate Owned LLVM ELF shared dynamic ABI (stacked
PR #133) passed **9/9** real local Clang17/GCC14 tests, including four
positive + four wrong-code native C caller executions. Those tests are
not an execution of the full Hepta checkout.

The current container does not have the pinned native Rust/Clang20
whole-repo checkout or all platform hosts. The new
`tests.test_object_executable_exports` and
`tests.test_llvm_ssa_target` source changes are committed for replay,
not incorrectly reported as having passed on this exact new head.

A reproducible native invocation in an appropriate exact checkout:

    python -m unittest tests.test_object_executable_exports tests.test_llvm_ssa_target tests.test_llvm_ssa_integration -v
    python -m unittest tests.test_elf_shared_abi_native tests.test_llvm_owned_backend -v
    python -m unittest discover -s tests -v

## Production blocker ledger remains open

P0 exact source whole-suite results, P1 general owner/loan/drop/provenance
soundness and source-to-LLVM refinement, P2 independent complete Rust
compiler, P3 complete C pointer migration and bidirectional physical hosts,
P4 full C++ RAII/STL/templates/exception safety and ABI, P5 full
workload and stable fair performance gates, P6 real-model Agent 2x2
productivity/cost and crash-safe multi-file transactions, P7 physical
DMA/MMIO/IRQ boards and GPU remain open.

This gate checks object *structure and declared symbols*, not instruction
correctness, C++ ABI compatibility, arbitrary foreign pointer safety,
loader behavior or machine-code functional equivalence.

Do not set `whole_project_blockers_closed=true` or call any
historical report a qualification of the final integrated head.


## Source-facing second-publication race closed (P5 increment)

The native backends had an inner compiler artifact publication which was
already protected by the PR #127 staged-inode/bytes check. However, the
outermost source build uses an **additional** no-overwrite hard link from
native backend output to the final destination. This final link is a distinct
publication boundary; previously its bytes could be changed after the last
stage validation but before emitting a successful source-build receipt.

Both `build_llvm_ssa_source` and `build_llvm_owned_source` now reuse the
existing `llvm_ssa_target._verified_publication` helper **after the final
hard link**: the destination must be a regular file pointing to the exact
stage inode, the descriptor and pathname identity must stay unchanged during
the read, and all destination bytes must equal the stage-checked bytes. The
success receipt uses those independently re-read published bytes. The Owned
LLVM pipeline maps helper errors to the specific
`E_LLVM_OWNED_PUBLICATION` failure.

New actual-source integration negative tests in
`tests/test_llvm_ssa_cli.py` and `tests/test_llvm_owned_backend.py` patch
the *second* hardlink operation so a concurrent writer corrupts only the
outermost destination. Those tests require full native Rust/Clang20 to run;
they are **committed but not executed on this integrated SHA**. Their
presence does not establish same-user filesystem adversary isolation or
guarantee absence of mutations after the validation returns. It makes the
before-success receipt fail closed on the tested race window.

Replay the new source publication attacks with:

    python -m unittest tests.test_llvm_ssa_cli tests.test_llvm_owned_backend -v

