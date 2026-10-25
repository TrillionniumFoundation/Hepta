# P3/P5: native Linux x86_64 LLVM object ↔ GCC C ABI execution

Exact stacked base: PR #78 `16fa508888de854f831e031181891618107e50a1`.

## New executable validation

`tests/test_llvm_ssa_linux_host_abi.py` runs on an **actual** Linux x86_64
host with Clang and GCC. A strict i32 LLVM IR fixture is compiled with
`compile_ssa_target_object`, including the format/section/symbol gates,
then linked into a separate GCC C caller at -O0 and -O2 and executed.

An independent 2×2 native Clang-object/GCC-caller optimization matrix
also compiles an intentionally wrong LLVM implementation and requires
the caller to reject it (exit 17). Every native process invokes bounded
stdout/stderr/wall-time capture. The C caller exercises 2001 finite signed
integer values in a domain without signed overflow.

## Measured independent host probe

An independently executed local Clang 17 + GCC host probe completed
four correct runs and four compiled wrong-implementation rejections,
each over 2001 input values. See conversation attachment
`hepta_llvm_gcc_host_abi_20261025.json` for compiler identities,
binary SHA-256 values, source hashes, and raw exit statuses.

## Evidence scope

The LLVM fixture is supplied directly, not generated from a Hepta
source/borrow-validated HSIR or resource checked application.
This provides one real Linux x86_64 Clang/GCC scalar C calling convention
witness, **not** generalized C/C++ ABI compatibility, native LLVM backend
semantic refinement, Windows/macOS/ARM64 runtime, real hardware/GPU,
general Rust-grade safety, or complete P0–P7 production acceptance.
`whole_project_blockers_closed=false`.

Reproduce: `python -m unittest tests.test_llvm_ssa_linux_host_abi -v`.
