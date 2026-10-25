# P5: LLVM scalar native codegen strict source-profile boundary

The `SSA_LLVM_IR` carrier previously accepted a matching SHA-256 and enumerated
exported names, but a caller could construct a new LLVM module with extra
external calls, memory instructions, inline assembly, or global definitions,
recompute the SHA-256 and submit it directly to either native compile entry.
That hash asserts text integrity, not checked-source provenance or safety.

`hepta.llvm_ir_profile.validate_scalar_llvm_profile` now confines source
accepted by `SSA_LLVM_IR.check_identity` to the exact scalar generator header,
allowed three checked-overflow intrinsics, abort declaration, i32 functions,
PHI/assignment/icmp/branch/return patterns, and closed intra-function labels.
Both host shared library and five-target object compilers invoke this before
Clang, rejecting arbitrary rehashed LLVM IR and preventing publication of a
native artifact on rejected input. The existing independent scalar SSA verifier
continues to run *when emitting* the LLVM source.

Qualification:
- `python -m unittest tests.test_llvm_ir_profile -v`: pure source tests plus real Clang object.
- `python -m unittest tests.test_llvm_ssa_backend tests.test_llvm_ssa_target -v`: end-to-end original emitter and rehashed hostile IR rejection.
- Standalone source-profile gate is intentionally not a source-to-IR refinement
  proof, nor a soundness theorem for arbitrary Python callers that can forge
  well-formed pure i32 IR. It does not establish ownership/provenance proofs,
  complex C++ migrations, ABI compatibility or performance dominance.

The broader P0-P7/P01-P12 ledger remains OPEN.
