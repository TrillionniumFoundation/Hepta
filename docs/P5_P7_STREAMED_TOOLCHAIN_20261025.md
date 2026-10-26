# P3/P5/P7 bounded native toolchain identity — unified compiler candidate

Date: 2026-10-25. Exact base: PR #149 at
80da2e7ec168eaf308475a7f2178b92280066321.
Source branch: agent/hepta-p5-p7-streamed-toolchain-20261025.
This is a scoped native resource/correctness increment, NOT a P0-P7
production release or memory-safety theorem.

## Confirmed compiler resource gap

The main C project migration already streamed native compiler SHA-256, but
the strict scalar and Owned LLVM backends were still reading the complete
selected Clang executable into memory to hash it. Clang/LLVM binaries can
be hundreds of MB; this imposes compilation-time memory overhead unrelated
to the program being compiled. Some paths hashed only AFTER compilation,
without comparing the executable's content identity before native codegen
with the executable after native codegen.

## One shared implementation

The new hepta.native_tool_identity.digest_executable is the ONLY new hashing
implementation. It streams SHA-256 with 1 MiB reads; accepts only ordinary
regular files with a finite 1 GiB file-size ceiling; checks file identity
and mtime/ctime before and after the read through the opened file descriptor
and the original path; fails closed on missing, empty, oversized, symlinked,
retargeted or special files, and files truncated/mutated during reading.

It is now used by:
- hepta.c_project native compiler identity at both capture/replay;
- hepta.llvm_ssa_backend host scalar LLVM;
- hepta.llvm_ssa_target cross ELF/COFF/Mach-O scalar object compiler;
- hepta.llvm_owned_backend host Owned LLVM;
- hepta.llvm_owned_aarch64 AArch64 Linux Owned LLVM object compiler.

All LLVM compilation entrypoints bind the actual compiler hash BEFORE
native execution and require identical streamed content immediately BEFORE
artifact publication. Existing independently checked Resource IR and
semantic HSIR, object layout/symbol rules, and no-overwrite publisher
remain unchanged and authoritative. This does not attest that Clang was
compiled correctly or that an external OS loader is trustworthy.

## Real local validation performed

The exact Git blob of the committed helper
231e44d443a0bd77bb9caf30072d1ba3d7dcc8db was copied to local Python
3.13 and checked against git hash-object. Its companion regression test
Git blob 0a245df1414c69e6512f52d2a8a7c0229f1fe28d ran 8/8 local
tests with no skip: correct SHA, no whole-file read, missing/empty file,
symlink, FIFO, sparse 1-GiB+ oversize, in-place truncate after open,
compiler path retarget after open, and real Clang executable digest.

An additional local real Clang 17 exercise (actual executable size
172,313,240 bytes) used the same helper before/after compiling LLVM IR:
- x86_64-unknown-linux-gnu ELF64 object: 608 bytes, machine 62;
- aarch64-unknown-linux-gnu ELF64 object: 632 bytes, machine 183;
- pre/post compiler digest unchanged.

The complete Hepta worktree, pinned rustc, Rust borrow qualification and
full native multi-target compilation tests were not available locally.
Only the helper's EXACT committed code and its regression tests are
reported as locally executed; no full Hepta native build is claimed.

## Limits and open blockers

The 1-GiB cap is an explicit finite toolchain profile. The compiler path is
canonicalized by existing callers before hashing, but path/content hashes
alone do NOT cryptographically attest tool provenance, tool execution,
physical target ABI or compiler correctness. This remains source-to-object
engineering qualification, not a backend-refinement proof.

P0 full branch unification; P1 general Borrow/Drop/Provenance formal
source-to-HMIR refinement; P2 Rust compiler-core port; P3 full C pointer
migration and real diverse host C ABI; P4 C++ templates/RAII/STL/MSVC;
P5 general native backend semantic equivalence/performance; P6 actual
Agent model productivity/cost and crash-safe workspace evidence; P7 physical
DMA/MMIO/IRQ/GPU and long-run stability remain OPEN or PARTIAL.

Never set whole_project_blockers_closed=true on this increment.
