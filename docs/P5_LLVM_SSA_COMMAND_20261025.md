# P5: Strict source-to-native LLVM SSA CLI

The public `hepta build-llvm-ssa SOURCE --output FILE` command wires the
**single canonical** Hepta semantic encoder to the existing restricted
HSIR/CFG/SSA analysis and direct LLVM SSA backend. A native Rust reference
check with actual rustc evidence is mandatory. The independent structural
SSA verifier is invoked before emitting the LLVM source, and its digest
is cross-checked against the emitter's recorded source.

When no `--target` is given, the compiler produces a host shared library.
An explicit `--target` produces a *cross-object only* file on the
documented Linux/Windows/macOS x86_64/ARM64 target profiles; no cross-target
execution or cross-C-ABI guarantee is implied.

The command stages its native artifact inside the output filesystem and
publishes with `os.link` no-replace semantics only after the exact loaded
source project remains unchanged. Existing files, leaf symlinks, missing
directories and aliasing input files reject. Noncooperating filesystem writers
and malicious same-user mutation are outside this guarantee.

## Examples

```sh
hepta build-llvm-ssa examples/llvm_scalar.hepta -o /tmp/scalar.so
hepta build-llvm-ssa examples/llvm_scalar.hepta --target aarch64-unknown-linux-gnu -o /tmp/scalar.o
```

The report is `hepta.build-llvm-ssa.v1` with source/compiler/IR digests,
native backend object identity, exact applied subset, explicit failing
diagnostics, and false claims for full backend refinement, C ABI qualification,
whole-language soundness and target execution. The compiler does not silently
fall back to Rust or C when direct LLVM rejects a construct.

**P5 remains partial.** Acceptance requires a unified source/IR refinement
argument, real cross-toolchain ABI testing, performance data, general typed
ownership/provenance/effect lowering, and the unchanged source HEAD full gates.
