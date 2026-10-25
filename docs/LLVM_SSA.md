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

## P6 scoped performance and process resource receipt

The independent tool `tools/ssa_native_benchmark.py` accepts the actual
native `build-llvm-ssa` shared-library artifact, builds a separate native
C function with the same finite loop behavior using the exact host Clang,
and tests known C-defined inputs before measuring. A separately compiled
C timing driver invokes each function directly via `dlopen`/`dlsym`, outside
Python per-call overhead. Trials alternate in seeded pseudo-random order;
raw elapsed nanoseconds, nanoseconds/call, process peak RSS, compiler binary
and shared-object SHA-256 identities are saved to a versioned JSON report.

Run (on Linux, with a trusted native binary and a preexisting output folder):

    python -m hepta build-llvm-ssa examples/ssa_llvm.hepta -o /tmp/hepta-ssa.so
    python tools/ssa_native_benchmark.py \
      --library /tmp/hepta-ssa.so --symbol hepta_accumulate \
      --output artifacts/p6-ssa-perf.json --trials 7 --iterations 15000
    python -m unittest discover -s tests -p test_ssa_native_benchmark.py -v

Important qualification limits:

- This tool **loads and runs native code**. Never run an untrusted generated
  binary without an externally enforced OS sandbox. The benchmark program
  and its subprocess time limits are not a sandbox.
- Measurements apply only to the declared host, bounded function and finite
  input domain. Different CPU, compiler, flags or affinity may change ratios.
- Peak RSS is the entire driver process including the dynamic loader and
  libraries, **not a proof of zero heap allocations in the tested function**.
- Samples are not application-service p95/p99 latency, not hardware power
  evidence, and not a statistically qualified Rust/C++ performance advantage.
- A missing report, failed correctness check or incomplete native compile is
  never a passing benchmark or a language-wide performance claim.

Full P6 production and P01–P12 acceptance remain open.

## P2/P6 target-object pilot (no target execution)

The separate `hepta.llvm_ssa_target.compile_ssa_target_object` consumes a
verified `SSA_LLVM_IR` and invokes real Clang with explicit `--target` to
produce a relocatable object on the destination filesystem:

| Triple | Object profile | Verified header identity |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | little-endian ELF64 relocatable | machine 62 |
| `aarch64-unknown-linux-gnu` | little-endian ELF64 relocatable | machine 183 |
| `x86_64-pc-windows-msvc` | COFF x64 | machine 0x8664 |

The object profile accepts precisely these targets; no target link, call
or emulation is performed, and the output refuses overwrite. Artifacts
carry the target triple, actual machine type, LLVM IR identity, prior SSA
verification identity, Clang identity and object hash.

    python -m hepta build-llvm-ssa examples/ssa_llvm.hepta \
      --target aarch64-unknown-linux-gnu --output /tmp/hepta-ssa-arm64.o
    python -m unittest discover -s tests -p test_llvm_ssa_target.py -v

Cross-compilation alone does not prove target-layout ABI compatibility,
runtime memory safety, Windows exception integration, successful linking,
or physical device execution. No target feature is silently qualified
by checking an ELF/COFF header. Full P2/P6 production gates remain open.
