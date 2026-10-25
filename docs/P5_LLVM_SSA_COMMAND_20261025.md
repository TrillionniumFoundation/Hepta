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

## No publication of invalid compiler receipts

The staged candidate object/shared library is hashed **before** final
hard-link publication and checked against the native backend's artifact
receipt. A deliberately wrong reported digest rejects without creating
the requested output file. This is a bounded artifact-publication
integrity check, not a guarantee against noncooperating filesystem
writers after publication or arbitrary malicious compiler behavior.

## Backend receipt must describe exactly the emitted IR and proof scope

The source command additionally checks the native backend status profile,
LLVM/SSA/independent verification digests, artifact size, exact cross-object
target where applicable, and explicit **false** semantic-refinement proof
claims. A backend record with a valid hash but elevated proof claims cannot
make the source command succeed. Negative tests use an intentionally forged
native receipt to demonstrate nonpublication.

## P5 narrow unsigned 32-bit support (2026-10-25)

The direct SSA/LLVM emitter now admits a **homogeneous** `u32` function
profile as well as its historical signed `i32` profile. Both produce native
LLVM `i32` values, but the *source type* controls semantics: unsigned
`ult/ule/ugt/uge` comparison predicates and unsigned checked
`uadd/usub/umul.with.overflow.i32` intrinsics replace the signed forms
where appropriate. Unchecked unsigned wrap is not silently introduced:
ordinary Hepta integer arithmetic still aborts on overflow. Mixed-sign
parameters, locals, returns and PHIs reject.

All-`i32` programs retain the historical
`hepta.llvm-ssa-i32.v0` IR profile. A module with `u32` functions
uses explicit `hepta.llvm-ssa-scalar32.v1`. Runtime tests include real
native Clang shared libraries, unsigned comparison boundary cases,
deliberate overflow abort, and a pinned Rust source-reference execution
path. **This does not qualify an independent general LLVM backend, C++ ABI,
cross-target execution, resource-bearing SSA or whole-language soundness.**
