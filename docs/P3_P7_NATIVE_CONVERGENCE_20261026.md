# P3–P7 native convergence: streamed tool identity, CPU layout and AArch64 synthetic link

**2026-10-26. Source integration only, not production release.**
All changes are based on the one canonical Hepta checked source/Resource IR/Owned
LLVM backend; no duplicate parser, backend, migrator or safety authority is added.

## Exact source lineage

- #149 `80da2e7ec168eaf308475a7f2178b92280066321`: one native compiler with C capture and ARM64 Owned LLVM object path.
- #151 `4c5fd56b0b6310b910f5b51740f1b7184dd32838`: native C target layout static-assertion probes for x86-64 and ARM64.
- #153 `9a9c799917c6c2fb19bca97b57b0827c6ce39042`: *optional, nonexecuted* AArch64 freestanding synthetic lld link probe and strict ELF symbol reader.
- #152 `3994e34f5a737edcb1a2c7085fbd96e55c14d8b8`: streaming regular-file Clang identity, 1 MiB chunks, finite 1 GiB budget, pre/post compilation replay.
- The first unified 6-file donor integration commit is
  `dfcbf2f85e0f0cf445b681c4988c3ba4f05d8cba`. These six exact blobs
  were imported only where their original preimage matched the #149 ancestor.

Two overlapping implementation files (`llvm_owned_backend.py` and
`llvm_owned_aarch64.py`) were explicitly reconciled. They retain the
mandatory real-target C ABI layout probe, the existing single Owned emitter,
the real ELF source/symbol checks, and pre/post **streamed** compiler binary
identity. The AArch64 source route additionally retains the optional synthetic
link flag. The resource and trusted AST authority remain untouched.

The synthetic ELF reader independently checks that every public function
symbol has nonzero byte length within SHT_PROGBITS + SHF_ALLOC + SHF_EXEC and
within **file-backed executable PT_LOAD** bytes, not just an unverified
section flag. A real static ARM64 ET_EXEC from Clang/lld passed the finite
check. Changing executable .text to SHT_NOBITS and shrinking file-backed RX
bytes while keeping `_start` inside the segment are explicit negative
controls. These are file verification checks, not runtime semantics.

## Exact-source acceptance needed

```sh
python -m unittest tests.test_native_tool_identity \
  tests.test_owned_target_layout tests.test_llvm_owned_aarch64 \
  tests.test_owned_aarch64_link tests.test_llvm_owned_backend \
  tests.test_c_project tests.test_llvm_ssa_backend \
  tests.test_llvm_ssa_target tests.test_llvm_owned_qualification -v
```

Use complete pinned Rust/Clang20 and real native toolchains to execute all
relevant release qualifiers against **this exact final integrated SHA**. Their
results must never be copied from an ancestor candidate. Do not suppress
negative controls or reduce the planned sample denominator. Work on other
features can continue without waiting for remote CI.

## Actual local toolchain observation

- Clang generated ELF64 `x86_64` and AArch64 C static-layout probe objects;
  altered `sizeof` assertions were rejected. Both paths require exact
  native symbol shape and have no imported runtime.
- Clang generated a 656-byte ARM64 native object for a small independently
  authored LLVM allocator example; lld linked it to a 1,536-byte ARM64
  ET_EXEC with a **deliberately nonfunctional** test shim, 8 exact public
  functions and no undefined symbols. A `getpid` dependency failed.
- Using those actual ELF bytes, the new executable-range checks accepted
  the real complete .text segment and rejected independently mutated
  SHT_NOBITS text and too-short executable PT_LOAD bytes.
- These checks did **not** run the complete Hepta compiler, do not prove
  memory-safety/refinement, and did **not** execute an AArch64 program.

## Important safety / production boundary

The synthetic shim returns null from `malloc` and does not implement actual
memory operations. **Never run or publish it as a user program.**
Object generation and symbol/link checks do not validate ABI calling
conventions, allocator correctness, target runtime behavior, board DMA/IRQ
or GPU/NPU execution. Every such claim stays false.

Remaining P0–P7 blockers include general ownership/provenance/lifetime
soundness, source→IR→native refinement, full C and C++ L2/L3 migration and
GCC/Clang/MSVC ABI matrices, production resource budgets and long-lived
p99, controlled real AI Agent A/B, functional ARM64 execution, physical
boards/DMAs and GPU backends. Keep `whole_project_blockers_closed=false`.
