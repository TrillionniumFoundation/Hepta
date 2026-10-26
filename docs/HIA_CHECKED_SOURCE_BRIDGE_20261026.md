# HIA P0/P1/P2: checked Hepta scalar -> executable HIA Program bridge

**Status: candidate code, not complete HIA Core v1 or production validation.**

## Purpose and exact trust chain

Do not create a second semantic checker or LLVM emitter. Retain the canonical
`hepta.semantic_ir` authority, existing `hepta.hsir` scalar adapter, canonical
CFG/SSA/independent `ssa_verify`, `native_resource_gate` and
`hia_program.verify_program` as the executable Core verifier.

`hepta.hia_source_bridge.lower_checked_scalar_hia` receives an actual checked
Hepta AST plus exact project SHA. It reuses every existing frontend, resource,
CFG and SSA gate, then converts a **finite reviewed subset** to a versioned
standalone `hepta.hia.program.v1`. The destination Core is executable by the
existing HIA bytecode interpreter and accepted by its existing LLVM generator.
It is not an AST-rendered LLVM backend.

Input source SSA PHIs become explicit typed HIA block parameters. A bounded
backward liveness fixed point derives all cross-block SSA arguments, including
values forwarded through a loop and edge-specific PHI operands. SSA names are
hygienic, and the existing HIA verifier checks all resulting CFG/resource
transitions. The bridge rejects undefined nonlocal refs, missing PHI inputs,
noncanonical source/profile identities, unsupported effects, and untranslatable
expressions before any native code can be produced.

### Covered initial language profile

- Every function must be a C-exported homogeneous `i32` or `u32` function with
  zero to sixteen by-value parameters, no foreign assumptions or ownership
  values, and declared/inferred effects restricted to `panic`.
- Scalar arithmetic `+`, `-`, `*`, `/`, `%`, shifts, bitwise ops,
  checked negation, comparisons, byte-width-preserving typed values, wrapping
  integer casts, and internal Boolean predicates where the independent
  verifier accepts them.
- Straight-line computations, explicit branches, early returns, and while
  loops with SSA PHI joins and required value forwarding.
- **No** `&&`/`||` source short-circuit translation, because eagerly
  evaluating a trapping RHS would change source semantics. Source floats,
  generic owned aggregates, FFI, raw pointers, exceptions, `for`, `match`,
  calls, task runtimes and general provenance all reject.

### Native build entrypoint

`build_checked_hepta_hia_native` requires the *real*, pinned Rust reference
check through `analyze_project(..., native=True)` first. It then constructs
and verifies the HIA Core, invokes the existing
`hia_program_llvm.emit_program_llvm/compile_program_llvm` with **the verified
Core as the sole native program input**, and checks actual staged native
object, toolchain receipts, exact source graph identity before and after
compilation, and no-replace artifact publication. Any race or failed gate
must not publish a successful source-native receipt.

The native output is a Linux x86-64 shared/object or AArch64 object in the
existing LLVM target profiles; AArch64 object production is not target
execution. The compiled artifact is never claimed to be Rust codegen. A
successful build is still *finite native compilation evidence*, not an
independent proof that source and HIA are semantically equivalent.

### Isolated local evidence on original bridge source

The exact Python 3.13.5 source and in-repository test text were syntax-compiled
in this working container. A lightweight stub-based bridge harness generated
HIA blocks for straight-line, diamond and loop/PHI cases, executed 8 bounded
loop inputs with independent results, and rejected a `&&` short-circuit
case. **This was not a full Hepta repository unit run**: the stub harness
substituted upstream source/resource checkers and a finite HIA interpreter.
The committed `tests/test_hia_source_bridge.py` uses the **real** Hepta parser,
checker, independent Resource IR gate, SSA, HIA verifier/interpreter and LLVM
source emitter; it still requires execution in a complete exact-source
checkout. No real rustc or Clang-native final artifact was built here.

## Follow-on closure blockers

1. P0: reconcile newest stacked PRs, versioning and executable Core
   compatibility before merging into main.
2. P1: full numeric/memory/resource SSA beyond homogeneous integers, named
   lifetimes, owned aggregates, FFI provenance and exception/drop edges.
3. P2: actual exact-SHA native differential execution against pinned Rust,
   including overflow traps, owner failure paths, loop/PHI corner cases;
   then formal source->Core and Core->LLVM refinement arguments.
4. P3-P7: cross-compiler native ABI, general C/C++ conversion, real Agent
   economic A/B, physical DMA/GPU and representative production workload
   qualifications remain independent blockers.

`whole_project_blockers_closed=false`.
