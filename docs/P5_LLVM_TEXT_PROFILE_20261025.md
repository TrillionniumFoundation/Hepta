# P5: SSA LLVM text compilation-boundary confinement

The LLVM SSA native APIs previously accepted public `SSA_LLVM_IR` objects
whose text and function-name inventory matched an attacker-recalculated SHA.
The object could contain unrelated LLVM declarations, native calls or memory
operations despite reporting the same unverified SSA receipt strings.

`hepta.llvm_ir_profile.validate_scalar_llvm_profile` now requires the
emitter's exact fixed module header and declaration set, reviewed i32
SSA/PHI, checks, control-flow and abort syntax. Globals, load/store/alloca,
inline assembly, non-whitelisted calls and LLVM metadata reject before
either host shared-library or cross-target object compilation.

Branch-target and block-terminator checks plus source-SSA and verifier hash
shape checks are additional integrity gates. The new tests rehash malicious
IR deliberately, rather than relying on detecting stale fingerprints.

## Scope

This is a fail-closed *text syntax* profile, not proof that an input was
originally emitted by the valid CFG/SSA lowering. Hashes are not
cryptographic attestations when a caller can recompute them. Source-origin
proof, backend refinement, FFI safety, full provenance and generalized
LLVM optimization are still OPEN. This stage does not broaden accepted
language constructs or qualify production native platforms.

Reproduce: `python -m unittest tests.test_llvm_ir_profile tests.test_llvm_ssa_backend tests.test_llvm_ssa_target -v`.
An independent eight-case local validation of the lexical gate plus two
real Clang fixture compilations was performed before integration, but full
Hepta repository tests are not claimed until actually executed.
