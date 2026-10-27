# P0–P7 continuing integration: bounded C projects and AArch64 Owned LLVM

**Working source code, not complete production qualification.**

This checkpoint is stacked on the strongest source-bound #144 integrated compiler:
`ba90aae079926e916af72982b0f70ab6c9b890d2`.

Source integration commit:
`b41e5a5dca289a8e2aa8f4ceb8eb6c8121c9360b`
Exact tree:
`c760be2a01d982922bc9f5a3502f0c99b7c6c71c`.

This commit imports **7 unchanged file blobs** from two independent PR heads,
with no overlapping paths. It preserves the existing canonical semantic IR,
Rust reference gate, SSA/resource verifiers, Owned LLVM backend, foreign ABI
scanner, artifact publisher, C/C++ migrators and Agent Workspace.

| Scope | Donor | Real increment |
| --- | --- | --- |
| P2/P3 | #148 `4aaf7c611760ba2f2e6e2bb39c948367f92b933a` | Closed C compile-database intake, nonfinite/duplicate refusal, bounded data, typed capture/source replay |
| P5/P7 | #147 `6a0b33a0357b7f804ede06d49ad49c9709de0dd9` | Direct source-bound Owned LLVM to real AArch64 Linux ELF relocatable, exact export/import inventory, staged publication |

## Check source without waiting for remote CI

```sh
python -m unittest tests.test_compdb_intake tests.test_c_project \
  tests.test_llvm_owned_aarch64 -v
python -m unittest tests.test_resource_ir tests.test_native_resource_gate \
  tests.test_llvm_owned_backend tests.test_artifact_publication -v
```

Record full native builds and target-specific commands with exact source,
LLVM, compiler and artifact digests. A previous source SHA's passing evidence
does not qualify this integration.

## Direct execution observations this session

Local Clang generated two actual AArch64 ELF64 relocatable objects from
manually defined LLVM smoke source, both with `clang` exit 0:

- 656-byte allocator/free control: machine AArch64, a defined text symbol
- unexpected `getpid` import control: AArch64 ELF64 object with a defined
  `checked_owner_length` symbol and unresolved `getpid`

This proves Clang target-codegen and illustrates the negative import case,
**not** complete in-repository Hepta execution or source/ABI equivalence.

## Remaining blockers, with no false closure

P0/P1: full Rust-equivalent ownership/lifetime/unsafe formal soundness and
source-to-IR/backend refinement remain open.

P2/P3: automatic arbitrary C/C++ conversion, target-specific layout and
cross-compiler ABI on live target systems remain open.

P4: general RAII templates, nontrivial C++ state and exceptions across the
ecosystem remain unsupported.

P5: complete Owned LLVM semantics and representative unbiased production
resource/p99 performance gates remain incomplete.

P6: no actual comparable 2x2 live-model Agent trials with cost receipts.

P7: no executed AArch64 target runtime from this source, physical board,
DMA/cache/IRQ coherence, GPU/NPU backend or real-device qualification.

**`whole_project_blockers_closed=false`**. Keep this PR in Draft until
the exact-source native and adversarial proof/replay gates have receipts.
