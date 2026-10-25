# P3/P5 — Linux x86_64 actual C consumers for direct scalar SSA

`tests.test_llvm_ssa_host_c_abi` compiles a real SSA/CFG fixture through
the existing independent Hepta SSA verifier and direct LLVM backend into a
shared library. A *separately compiled* C11 program links and calls that library.

Both `gcc` and `clang` compile the native C consumer at `-O0` and `-O2`.
Each executable checks multiple signed-int inputs against the frozen source
CFG interpreter. A second compiled C implementation with a deliberately
wrong return value must fail the exact same consumer program; an exit code
of 23 is required to prove the harness rejects the mutant.

This is **one actual Linux host scalar ABI direction**, not a macOS/Windows
target execution receipt, C++ ABI, hardware, ownership or proof of general
LLVM source-semantic refinement. It starts from SSA fixtures rather than
a full Hepta source and is distinct from the broader P5 migrated-source
differential test on PR #52.

Local separate independent compiler probe, not identical to this repository
test: 4 GCC C/LLVM host compiler/optimization positive and 4 compiled
negative variants were executed with 2,001 input comparisons per run.
The local receipt is `/mnt/data/hepta_llvm_gcc_host_abi_20261025.json`.
The new repository-native fixture test still requires its own run on
this exact source version.
