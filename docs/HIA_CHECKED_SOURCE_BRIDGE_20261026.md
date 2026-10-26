# HIA P0/P1/P2: checked Hepta scalar -> executable HIA Program bridge

**Status: candidate code, not complete HIA Core v1 or production validation.**

## Purpose and exact trust chain

Do not create a second semantic checker or LLVM emitter. Retain the canonical
`hepta.semantic_ir` authority, existing `hepta.hsir` scalar adapter, canonical
CFG/SSA/independent `ssa_verify`, `native_resource_gate` and
`hia_program.verify_program` as the executable Core verifier.

`hepta.hia_source_bridge.lower_checked_scalar_hia` receives an actual checked
Hepta AST plus exact project SHA. It reuses every existing frontend, resource,
CFG and SSA gate, seals the existing legacy scalar HIA Core, then calls
**the already existing** `hepta.core.from_scalar_core` to convert its verified
SSA/PHI subset into standalone `hepta.hia.program.v1`. This module introduces
**no separate SSA conversion algorithm**. The resulting Core executes using
the existing HIA interpreter and LLVM backend.

The existing `core.from_scalar_core` owns SSA-PHI-to-block-argument conversion,
including bounded liveness and predecessor-specific PHI edge binding. The
old scalar native profile is revalidated before conversion, and the new HIA
verifier checks the resulting program. Untranslatable semantics and source
identity mismatches reject; no new semantics are inferred.

### Covered initial language profile

- Every function must be a C-exported homogeneous `i32` or `u32` function with
  zero to sixteen by-value parameters, no foreign assumptions or ownership
  values, and declared/inferred effects restricted to `panic`.
- The **existing** `core.from_scalar_core` mapping of `+`, `-`, `*`,
  comparisons, integer/Boolean literals, source references and checked unary
  negation. Division, remainder, shifts, casts and other operations are not
  yet admitted by the reused old-scalar-to-HIA adapter.
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

Command line (requires the same pinned rustc and Clang20+ expected by the
existing native HIA backend; this does not execute the compiled artifact):

```bash
python tools/build_checked_hia_source.py examples/llvm_scalar/main.hepta \
  --rustc /path/to/pinned/rustc --clang /path/to/clang \
  --target x86_64-unknown-linux-gnu --kind shared -o /tmp/new-output.so
```

The CLI prints a source/binary bound JSON receipt and exits nonzero on any
failure. It never automatically falls back to another compiler backend.

The native output is a Linux x86-64 shared/object or AArch64 object in the
existing LLVM target profiles; AArch64 object production is not target
execution. The compiled artifact is never claimed to be Rust codegen. A
successful build is still *finite native compilation evidence*, not an
independent proof that source and HIA are semantically equivalent.

### Isolated local evidence on original bridge source

The exact Python 3.13.5 source and in-repository test text were syntax-compiled
in this working container. The initial standalone converter prototype was locally smoke-tested for
straight-line, diamond and loop/PHI cases (8 bounded loop inputs) and then
**removed** after discovering the existing `core.from_scalar_core`. The
final source module passed syntax checks and a stub-only orchestration test
that verified it calls the canonical converter and rejects invalid project
identities. The eight earlier loop comparisons are evidence about the discarded
prototype, **not** this final reused-converter implementation. Full-source
parser/checker/native tests remain unexecuted in this environment.
The committed `tests/test_hia_source_bridge.py` includes ten methods with
stale-graph and no-rustc nonpublication controls, using the **real** Hepta parser,
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
