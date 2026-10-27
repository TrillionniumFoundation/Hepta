# P0–P6 exact-blob integration on the current unified Owned LLVM candidate

Date: 2026-10-25. This is a **stacked engineering checkpoint**, not a
whole-language safety, migration or production-release qualification.

## Source ownership and exact ancestry

- Current production-oriented compiler authority remains PR #115:
  `implement/hepta-unified-native-20261025`, source/evidence HEAD
  `a04ae789b2348504089e2c3484178998a6f332ba`.
- The immediately preceding stacked PR #133 contributes a bounded ELF shared
  dynamic ABI verifier. Parent exact commit for this integration:
  `a60e7344bf07b510e570fa9fb582da130e13ab94`.
- Donor aggregate PR #127 exact head:
  `68f165d0d88e860297f39fc60b06e34a7049835e`.
- Donor's original base:
  `ddbc428a52c79484f27c66832341d2b154c52165`.
- Exactly **14 donor paths** were transplanted as original immutable Git blobs
  using one new Git tree. Each path was independently checked: the parent
  (pre-change) blob at the current source head was exactly the donor's old
  base blob, or both paths were absent for a new file. No unrelated source
  file was replaced and no parallel compiler/HSIR authority was introduced.

## Preserved donor guards

| Scope | Existing implementation integrated verbatim |
| --- | --- |
| P0 | Release evidence identity regression tests |
| P1 | Typed SSA source-origin, PHI, owner/metadata non-forgery tests |
| P2/P3 | Clang C compilation database typed dependency/ABI provenance |
| P4 | C++ class migrated file byte/inode provenance |
| P5 | Native scalar LLVM cross-object publication identity |
| P6 | Typed Agent contract-diff, lifetime and volatile-site guards |
| Test/document | Corresponding donor tests and PR #127 review checkpoint |

The fifteenth PR #127 donor file `tools/release_check.py` was **not**
transplanted wholesale. The current PR #115 release runner has added 46-gate
resource/LLVM/native/Agent qualification behaviors. Blind replacement with
the older donor would silently remove those conditions.

Instead, the same `_evidence_state` / `_read_regular_evidence` security
algorithm was applied to the current 46-gate runner:
- require a stable regular filesystem entry;
- refuse symlinks, FIFOs, missing paths and replaced open-file identities;
- compare file identity before/during/after the read;
- retain old-versus-new evidence identities and every original gate/status;
- explicitly fail closed if the pre-producer evidence state was unreadable.

The donor's existing `tests/test_release_file_identity.py` is present on the
new branch unchanged. This is a manual **source-level reconciliation** of the
only shared source file, not an unreviewed merge of competing toolchains.

## Qualification facts, not claims

The 14-blob ancestry and exact source hash equality were verified from GitHub
Git trees on the actual parent and donor SHAs. The earlier #133
`hepta.elf_shared_abi` and `tests.test_elf_shared_abi_native` exact-file
tests ran **9/9** locally under Python 3.13.5, Clang 17 and GCC; that isolated
test run is bound to their bytes, not this branch's full toolchain.

The P0–P6 combined Python/Rust/Clang20/Lean/QEMU/native regression suites
**have not been executed on the final integration SHA** in this isolated
container. The current source inherits historical #115 evidence of 1,369
passing tests and 44/46 release gates (two failed performance stability
conditions), but those receipts belong to the exact older compiler snapshot.
Do not relabel them as final-integration passes.

Useful source commands:

    python -m unittest tests.test_release_file_identity tests.test_ssa_verify tests.test_ssa_scalar tests.test_c_project tests.test_cpp_class_migrate tests.test_llvm_ssa_target tests.test_agent_contract_diff tests.test_agent_semantics -v
    python -m unittest tests.test_elf_shared_abi_native tests.test_llvm_owned_backend -v

## Still-open production research and engineering

Full Ownership/Borrow/Drop/Provenance semantics and source/LLVM refinement,
a Rust-native compiler with complete diagnostic parity, broad C project
migration and C++ RAII/STL/template/exception equivalence, physical Linux/
Windows/macOS/ARM ABI qualification, complete resource budgets and task/I/O
proofs, stable native performance reproducibility, real Agent-model 2x2
cost/quality comparison, GPU and board-level DMA/MMIO/IRQ remain unqualified.

Keep both stacked PRs Draft and
`whole_project_blockers_closed=false`. No CI result or historical
source receipt is used to waive an unproven property.
