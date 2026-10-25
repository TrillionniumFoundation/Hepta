# P1: PR14 HSIR scalar source → PR37 CFG/SSA integration

This patch extends PR #55 with the missing actual producer conversion:
PR #14 source_bound_v0 → a strictly checked, PR #36-shaped frozen_snapshot_v0
→ existing PR #37 CFG / scalar SSA / independent SSA verification.

## Using the implemented import route

On the PR #53 codebase, export:

    python -m hepta hsir-v1 project/sample.hepta --frontend-only > /tmp/sample-hsir-v1.json

Then in a checkout with this PR stacked on PR #37, inspect (not build):

    python -m hepta ssa-v1-import /tmp/sample-hsir-v1.json

The result is hepta.ssa.integration.v1, binds original v1 → original v0 →
mapped v0 → CFG → SSA → verification identities, and explicitly leaves
source semantics, memory safety, foreign contracts and native codegen
authorization false. The separate existing ssa-v1-verify SOURCE command
still requires PR #37's native Rust reference gate. The import command
performs **no** native source check; its input is untrusted, and even a
forged wrapper validation status never becomes a native proof.

## Admitted profile

Plain by-value i32/u32/i64/u64/bool parameters, root-level locals, scalar
arithmetic/comparisons, if/else, while, assignments and explicit returns.
Operations have bounded recursion, size, exact field shapes and checked
expression arity. Independent binding validation rejects undeclared variables,
type mismatches, immutable writes, bad return/initializer types, shadowing,
out-of-width integers and falsely omitted panic effects.

Ownership and ABI are **not** weakened to meet the subset. Nonempty external
obligations, FFI, raw pointers, borrowed parameters, heap/Task/Buffer,
generics, stored lifetimes, nonempty resource contracts, cross-source spans,
nested-local shadowing, unmodeled operations or declarations reject before
CFG/SSA. A hash identifies claimed bytes but does not prove the bytes came
from a real checker or that transformation preserves behavior. No fallback
to LLVM emission or C/C++ wrapper execution exists on the import path.

## Qualification and remaining blockers

- Locally run on Python 3.13.5: 14 v1 baseline tests, 31 bridge tests,
  15 additional bridge regression tests and 4 mocked SSA adapter tests:
  **64/64 passed**. Only the 4 adapter tests use CFG/SSA stand-ins; all 64
  are bounded frontend-independent tests. These results are not native Hepta
  compiler qualification.
- tests/test_hsir_v1_scalar_integration.py (15 focused tests) is committed
  together with the bridge. tests/test_hsir_v1_cli_import.py adds 4 real-CLI
  positive/negative tests and is **committed but not locally run**, because
  the full PR #37 source checkout is not present in this tool environment.
  tests/test_hsir_v1_ssa.py remains the full project CFG/SSA verification
  regression target and also requires the complete project.
- Original PR #14 owned-resource and stored-borrow semantics are not
  lowered into scalar SSA by this patch. Separate ownership/provenance-aware
  IR, refinement proofs and backed-native evaluation remain P1 blockers.
- General C migration, C++ safety, cross-architecture ABI, resource
  efficiency, real model experiments and physical hardware remain P2–P7
  blockers. No CI status is used in this review. This is an isolated
  incremental branch; do not treat it as closing whole_project_blockers.
