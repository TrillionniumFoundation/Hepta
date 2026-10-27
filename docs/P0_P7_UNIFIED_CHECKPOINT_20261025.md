# Hepta P0–P7 integrated engineering checkpoint — 2026-10-25

**Candidate, not release qualification.** This integration is a source-level
merge of disjoint, exact Git blobs from six independently scoped draft PRs.
It does **not** inherit the 40/40 gate result of the earlier, unchanged
`776f005d0f709c5033d513f113b4e4175e5be035` source checkpoint.

## Immutable integration inputs

Base code/evidence commit:
`ddbc428a52c79484f27c66832341d2b154c52165`.
Base validated **code**:
`776f005d0f709c5033d513f113b4e4175e5be035`.
Combined initial code commit:
`214c5247512e4ac1fc8c73d9798b2a3701cfeb31`.
Tree:
`01a2ee46c7060e2b3204a323d31756db48dcf3d2`.

| Stage | Exact source PR commit | Imported file inventory |
| --- | --- | --- |
| P0 | #120 `4ea7709edf466acf0c85e405a48314b5e5c62dc0` | `tools/release_check.py`, `tests/test_release_file_identity.py` |
| P1 | #122 `20f83c395f17c6256562626dbbe1c7174ab53ccc` | `hepta/ssa_verify.py`, `tests/test_ssa_verify.py` |
| P2/P3 | #123 `d5441ae31cf13fd40490c123465b416c1ade8fa6` | `hepta/c_project.py`, `tests/test_c_project.py` |
| P4 | #126 `52591c88252f57f086288be9a7622241b18335b5` | `hepta/cpp_class_migrate.py`, `tests/test_cpp_class_migrate.py` |
| P5 | #125 `4687289e9f34ea0b34b9d701d4eb1d6794976a44` | `hepta/llvm_ssa_target.py`, `tests/test_llvm_ssa_target.py` |
| P6 | #124 `e5773e71422336c20c03703b894c36d7b83f7322` | `hepta/agent_contract_diff.py`, `hepta/agent_semantics.py`, `tests/test_agent_contract_diff.py`, `tests/test_agent_semantics.py` |

Exactly **14 distinct files** were imported by unchanged Git blob object identity,
with no path-level overlaps. This establishes a deterministic combined source
tree, **not** semantic integration or native test success.

## Required immediate acceptance commands

From a full checkout of this **exact final integration commit** with its pinned
Python, Rust, Clang, GCC, Lean and QEMU tools where applicable:

```sh
python -m unittest \
  tests.test_release_file_identity tests.test_release_collection \
  tests.test_ssa_verify tests.test_ssa_scalar \
  tests.test_c_project tests.test_cpp_class_migrate \
  tests.test_llvm_ssa_target \
  tests.test_agent_contract_diff tests.test_agent_semantics -v

python tools/release_check.py --output-directory evidence/integration-rerun
```

The latter must retain actual per-gate receipts, bind the exact integrated
compiler identity and unchanged source snapshot, and record all rejected or
environment-blocked steps accurately. It may need a clean evidence output
directory and the exact toolchain from the repository's lockfiles. Native runs,
real devices and real AI model tests are **not inferred** from passing fixture
unit tests. Confirm that the qualified SHA is the final integrated SHA, not
the six source branches, and that no stale evidence is credited as fresh.

## Stage truth and outstanding production blockers

| Stage | Integrated code scope | What is still not qualified |
| --- | --- | --- |
| P0 | Native release evidence file identity; baseline audit and canonical HSIR selection inherited from unified candidate | Re-execute exact-source gates; whole-language source-to-IR refinement remains open |
| P1 | Scalar SSA source-literal origin, closed PHI/instruction inventory, existing resource IR | General stored loans, lifetime/type generics, pointer provenance, source/backend soundness |
| P2 | Compiler-captured C project provenance, strict boolean/integer metadata, Clang dependency replay | General C source/ABI semantics, unsafe pointer contracts, maintenance-cost evidence |
| P3 | C host/header qualification of selected shapes, strict capture of target ABI facts | Real all-target GCC/Clang/MSVC cross-ABI execution and arbitrary C++ ABI |
| P4 | C++ selected scalar-value-class migration with exact published generated text | General nontrivial resource-owning RAII, exceptions, templates, L2/L3 migration |
| P5 | Scalar32 SSA to LLVM, exact staged/published ELF/COFF/Mach-O object binding | Owned memory/borrow/Drop LLVM backend, representative resource benchmarks, semantic refinement |
| P6 | Pinned read-only Agent contract diff, type-faithful hardware/foreign obligations | Live model 2x2 A/B, full independent equivalence, controlled on-device workspace workloads |
| P7 | Original QEMU / Linux / Windows limited evidence remains separately attributable | Actual physical board, DMA, GPU/NPU, long-lived Linux/Windows/ARM services and failure recovery |

Never promote simulator/QEMU results to real-board execution; never present a
class wrapper or C++ foreign bridge as native source-level resource migration.
`whole_project_blockers_closed=false`.

## Merge policy

Keep the original source PRs and this aggregate as Draft until exact-HEAD
native results and integration review establish that all 14 source blobs work
together. Do not overwrite the original 40-gate evidence. Any further fix
requires a new precise HEAD and requalification.
