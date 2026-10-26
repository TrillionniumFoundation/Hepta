# HIA scalar executable semantics oracle v0

**Status:** finite numerical differential oracle, not a proven compiler
refinement or implementation of executable Owned/Loan/Drop semantics.

`hepta.hia_oracle.prepare_scalar_oracle(core, program, checked,
project_sha256=...)` is a strict source-facing entry. It first calls
`core.qualified_for` to replay canonical checked source, Resource IR,
CFG, SSA, and structural verification. It then invokes the **existing**
`emit_scalar_ssa_llvm` on the same verified SSA/CFG as a profile gate.
The returned `HIAScalarOracle.run(function, arguments, max_steps=...)`
interprets the verified SSA, **not** the source AST or generated LLVM text.
The preparatory source identity applies to the immutable snapshot used at
preparation, and is not a filesystem monitor or independent compiler proof.

The prepared SSA is retained as immutable canonical bytes and rehashed before
each evaluation; callers cannot mutate a nested Python dict while keeping the
previous prepared graph identity. This is an integrity guard, not a proof
against a malicious caller forging a new Python object.

## Explicit operational semantics

- Finite `i32` and `u32` inputs with strict integer-vs-bool checking.
- `int`, `name`, `bool` expressions, checked add/subtract/multiply,
  signed unary minus, comparisons with the selected signedness.
- Basic-block `goto` and `branch`; SSA PHI incoming values are read
  **simultaneously from the just-executed predecessor** before any PHI
  destinations are written. A static SSA register can acquire a new *dynamic*
  value on each loop iteration; claiming that SSA prohibits revisiting the
  instruction would misinterpret SSA semantics.
- Overflow raises `HIAOracleTrap` (a defined checked-arithmetic trap).
  Out-of-profile operation/input raises `HIAOracleRejected`. Budget
  exhaustion raises `HIAOracleBudgetExceeded`; it must NOT be counted as a
  semantic trap or proof that the program does not terminate.
- The interpreter has a bounded expression depth, explicit operation/step
  budget, and rejects unknown branches or SSA values instead of inventing
  native behavior. The native emitter remains the accepted operation subset
  authority; the oracle is an additional independent evaluator, not a codegen.

## Test and interpretation

`python -m unittest tests.test_hia_oracle -v` exercises real repository
parser/checker/Resource IR/SSA production, loop PHI, signed/unsigned
comparisons, checked overflow, stale-source rejection and zero arguments.
Where pinned Rust and qualifying Clang are installed, it also compiles a
source-facing LLVM shared ELF, invokes finite nontrapping inputs via ctypes,
and compares the native return to the independent oracle.

Never call an expected native `abort` through ctypes in the test process;
use an isolated child process when testing traps or fault injection.

An earlier local Python-only stub regression exercised interpreter loop
backedges, PHI, i32/u32 arithmetic, argument rejection, budget exhaustion and
checked overflow (5/5 unittest cases). **That does not execute the actual
Hepta repository or qualify the native LLVM backend.** The new checked-in
native test must be run on the exact source HEAD before claiming it passed.

No general memory, alias/provenance, FFI, multi-thread, GPU, arbitrary
C/C++ migration or Rust-better-than-universal performance claim follows.
`whole_project_blockers_closed=false`.
