# P5 source-to-host LLVM library identity gate

Stack: P4 PR #117 exact head `06c9e5a9f122efb6d7a6a14d2ebb14d258cf5fea`.

## Problem and fix

The existing `compile_scalar_ssa_llvm` code rejected nonzero Clang exits and empty outputs, but a successful compiler subprocess returning a nonempty wrong-architecture object or arbitrary data could still create a `native_host_compiled_unqualified` receipt and publish an unusable `.so`.

A new conservative `_host_library_identity` check inspects the actual **staged native bytes** before publication:
- Linux: ELF64 little-endian ET_DYN, exact x86-64/AArch64 host machine, bounded program headers, and file-backed PT_LOAD segments.
- macOS: Mach-O64 matching host CPU and MH_DYLIB, bounded load commands and LC_SEGMENT_64.
- Windows: PE32+ DLL with matching x64/AArch64 COFF machine and bounded section table.
- Unknown host/CPU or structurally invalid artifact: reject without publishing.

The SHA-256 and byte length in the returned receipt now come from validated staged bytes before the no-overwrite hard-link rather than a post-publication second read. This is a file container and target identity gate, not a proof of symbols, ISA correctness, compiler optimization or foreign ABI.

## Executed evidence

Actual standalone Clang 17 compiled LLVM IR into a Linux x86-64 shared object; `ctypes.CDLL` executed `hepta_probe(41)=42`. The independent Linux-format gate accepted that object and rejected fake bytes, a truncated header, ET_REL mutation, wrong machine ID and out-of-file program header: **6/6 expected outcomes**. Native artifact was 14,976 bytes in the observed run.

Repository tests in `tests/test_llvm_ssa_backend.py` additionally cover a mocked compiler returning exit code zero while writing junk; the final destination must not appear. These source tests are committed but the entire Hepta checkout/native pipeline is **not** executed in the current container.

## Open conditions

No full LLVM/MLIR language coverage, machine-level refinement proof, cross-toolchain C/C++ ABI, hardware runtime or general Rust performance claim is made. P0–P7/P01–P12 remain open/partial, `whole_project_blockers_closed=false`.
