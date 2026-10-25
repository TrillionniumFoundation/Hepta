# P1 independent scalar reaching-definition acceptance

Exact parent: PR #83 head `b368f69080274baa976b7089ce5e70b08cafda3f`. This stacked P1 increment belongs to [PR #113](https://github.com/TrillionniumFoundation/Hepta/pull/113).

## Semantic bug and correction

Previously the independent scalar SSA verifier checked definition existence, type, use dominance and predecessor enumeration, but not the **particular value reaching** a program point. Re-signing the SHA-256 of a forged SSA was sufficient to:

- Replace both incoming PHI values at a diamond join with an older entry-block definition `x@0` that dominates both predecessors, even though the two paths assign `x@1` and `x@2`.
- Delete the live join PHI and read the pre-branch `x@0`, while making definition counts and versions self-consistent.
- Read `x@0` after an assignment to `x@1` in the same basic block.

The patch independently reconstructs the current scalar version at each block entry and exit from the validated dominator tree. It compares every PHI input with the exact predecessor exit version and every read with the current version. Source liveness determines whether a missing PHI is required: dead divergent values do not trigger false rejections.

Earlier related fixes also reject zero-input PHIs at entry, local definition types inconsistent with source expressions and unreviewed nested SSA fields.

## Regression matrix and execution truth

Executable repository tests: `python -m unittest tests.test_ssa_verify tests.test_ssa_scalar -v`. Added source-bound positive diamond/backedge and dead-divergence controls, three reaching-value forgery negatives, a fabricated entry PHI and type/schema attacks.

An **isolated Python control-flow analog** was executed in the current local container: six controls passed (valid diamond, wrong PHI input rejected, missing live PHI rejected, legitimate dead divergent value accepted, stale same-block read rejected, valid loop). The analog uses synthetic dictionaries and does **not** execute the Hepta repository verifier or prove its integration. The GitHub branch's full native and unit suites remain **not run here** because the GitHub repository checkout cannot be mounted through this environment.

## Unclosed gates

This verifier applies only to the existing scalar/by-value CFG/SSA subset and its independently checked source snapshot. It is not a machine-code semantics proof, pointer provenance proof, general ownership/loan/Drop SSA, effect soundness proof, C/C++ equivalence or hardware qualification.

Keep `whole_project_blockers_closed=false`.
