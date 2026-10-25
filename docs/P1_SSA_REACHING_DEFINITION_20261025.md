# P1: Latest reaching definition is an SSA verification invariant

The independently checked CFG/SSA pipeline formerly verified name type, origin,
single assignment, dominance, and PHI predecessor inventories, but did not require
that a use refer to the *latest reaching source assignment*. A previously
dominating stale version can change computation while preserving original
expressions, CFG edges, and a freshly rehashed SSA snapshot.

## Implemented on this branch

- `hepta.ssa_reaching.reaching_states` independently computes scalar reaching
  versions from each block's predecessor edges. At entry, parameters have their
  real definitions and all other variables have an explicit uninitialized
  marker; ordinary statements, PHIs, and loop backedges update the state.
- An expression-name use must read a **single exact current** SSA version.
  A PHI incoming reference must match its predecessor's final version for the
  same variable. Missing PHIs, stale definitions, and ambiguous/uninitialized
  paths are rejected.
- `hepta.ssa_verify.verify_scalar_ssa` retains its original structural and
  source-expression checks and then independently checks latest reaching
  versions before reporting success.
- Adversarial regression cases include a straight-line overwritten local,
  a diamond PHI incoming edge, and a while-loop PHI backedge. In all cases
  the forged stale reference still *dominates* the use; this exercises the
  previously missing check rather than an existing dominance guard.

## Scope and validation boundary

A standalone deterministic Python mirror of the reaching-definition algorithm
was executed on the available host: 300 seeded valid straight-line scalar SSA
samples were accepted, all 300 deliberately stale-version mutations rejected;
manually constructed diamond and loop examples also accepted/rejected as expected.
This **does not** constitute an exact-source Hepta runtime test.

Reproduce full-project gate once the current branch is mounted:

```sh
python -m unittest tests.test_ssa_verify tests.test_ssa_differential -v
python -m unittest tests.test_llvm_ssa_backend tests.test_llvm_ssa_integration -v
```

This establishes a finite independent SSA def-use consistency invariant, not
a formal source-to-IR refinement theorem, lifetime/provenance model, full
ownership-aware SSA, compiler correctness, or production safety. Existing
P0–P7 / P01–P12 obligations remain open.

`whole_project_blockers_closed=false`.
