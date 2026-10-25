# Hepta P6 pilot: checked scalar SSA/PHI to native LLVM

This is a new, deliberately restricted direct backend for `i32` C-exported
functions containing scalar locals, conditionals, while loops and PHI nodes.
It **does not** use Rust- or C-source lowering for its final code generation.

Pipeline:

1. Parse and check the entire Hepta project, including pinned native Rust
   borrow/type validation using rustc 1.90.0 (CLI build path).
2. Serialize typed HSIR, structural CFG and pruned scalar SSA, rejecting all
   unsupported language forms rather than silently falling back.
3. Validate SSA structural origins, definition uniqueness, dominance and
   PHI incoming values against the original CFG.
4. Generate actual LLVM IR with i32 PHI, branches, a complete host symbol
   inventory and llvm.sadd/ssub/smul.with.overflow.i32 intrinsics.
5. Lower checked signed overflow into explicit abort branches. The LLVM
   predecessor label for each PHI is adjusted to the actual branch-exit
   continuation after any checked expression.
6. Compile with real host Clang into a nonempty native shared object;
   SHA-256 binds the LLVM, native artifact and native toolchain.

## Commands

    python -m unittest discover -s tests -p test_llvm_ssa_backend.py -v
    python -m hepta build-llvm-ssa examples/ssa_llvm.hepta \
      --clang clang --output /tmp/ssa-llvm.so

Only explicitly exported C i32 functions with 0–16 by-value i32 parameters,
i32 locals and return values are currently accepted. Declared/inferred
effects may contain panic only; external FFI assumptions are rejected.

The backend rejects floating point, pointers, borrowed slices, linear owners,
aggregates, calls, async effects, allocation, bitwise and short-circuit
expressions, range/for induction, match and unqualified ABI. Unsupported
constructs never trigger a silent fallback.

## Test evidence and limits

Five dedicated tests run under local Clang/LLVM with a manually constructed,
checksum-bound scalar CFG. Actual dynamic execution compares the resulting
shared library against an independent finite source-CFG interpreter, including
negative and positive loop bounds and seeded cases; a separately forked
signed-overflow input is expected to abort. There are also rejection tests
for ABI, effects, foreign contracts, tampering, and overwrite attempts.

These tests do not qualify the real Hepta source-to-CFG frontend; the CLI
requires a separate pinned native Rust reference check and exact-HEAD tests.

Never infer platform-general ABI compatibility, backend semantic refinement,
whole-language memory safety, or general superiority to Rust from this pilot.
Result state is `native_host_compiled_unqualified` and
`whole_p6_gate_closed=false`. Real C ABI cross-compiler/hardware qualification,
LLVM debug info, instruction selection, target matrix, memory/RSS and p99
regressions remain open.
