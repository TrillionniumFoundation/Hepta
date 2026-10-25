# P5: strict LLVM compilation input profile

The public native compilation entrypoints for the experimental scalar SSA
backend previously accepted an externally-constructible `SSA_LLVM_IR` if a
caller recomputed the text SHA-256 and reported the expected exported names.
That checked integrity, not that the text used the reviewed SSA codegen subset.

`hepta.llvm_ir_profile.validate_scalar_llvm_profile` is now required in
`SSA_LLVM_IR.check_identity`, which both host and target-object compilation
invoke before running Clang. It accepts exactly the emitter's bounded
declaration, i32/boolean, checked-overflow, PHI, branch and return vocabulary.
It rejects arbitrary imports, globals, alloca/load/store, inline asm,
extra functions, malformed blocks, and rehashed unknown instructions.

This is a fail-closed **input confinement gate**, not a proof the LLVM text
came from a particular original SSA snapshot. Independently checked SSA,
source-to-IR translation soundness, compiler trust and native target execution
remain separate obligations. P5/general production blockers stay open.

Negative tests forge rehashed IR and require an exact rejection prior to
native compilation. The per-file SHA is not used as an authorization token.
