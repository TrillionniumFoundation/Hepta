# P1 scalar SSA effect/resource binding (2026-10-25)

This is an incremental, narrow semantic preservation check on the existing **single canonical** Hepta source → HSIR → CFG → scalar SSA → independent verifier path. No second source checker, parser, borrow checker or LLVM backend is introduced.

## Implemented

- The scalar SSA lowering accepts only well-formed, sorted, explicitly declared **pure or panic-only** effects. The inferred set must be a subset of declared effects, with unknown, unsafe, FFI or other unsupported effects rejected.
- It validates the existing statically checked no-allocation/no-block/no-suspend/no-spawn clauses by exact type and value. This does **not** interpret general heap budgets or runtime scheduling.
- The SSA function carries the original declared/inferred Effects and resource contract; the independent verifier checks **exact equality against the source CFG** and rejects missing, modified or unreviewed function contract fields, even when a forged SSA snapshot has a freshly computed SHA-256.
- The verification receipt includes a source-contract digest and structural claim `effect_resource_metadata_matched_to_cfg=true`. This is not a new soundness/equivalence or global-resource proof.
- Regression tests cover a positive parser/checker/HSIR integration and adversarial effect upgrades, disabled resource restrictions, type confusion, dropped fields, forged metadata and stale source identity.

## Test entry points

```sh
python -m unittest tests.test_ssa_scalar tests.test_ssa_verify tests.test_hsir_bridge -v
```

These suites require a complete Hepta checkout and, for native qualification outside this module, the pinned toolchain. Test files committed to GitHub are acceptance inputs; without a same-snapshot execution receipt they are not claimed as passed.

## Still open

General owner/loan/Drop/provenance SSA, FFI and hardware effect semantics, source-to-backend semantic refinement, formal whole-language soundness, and cross-target native execution all remain open. `whole_project_blockers_closed=false`.

## Source metadata type-confusion guard

The independent verifier compares canonical JSON representations of the source
CFG versus SSA effect/resource metadata. Python dictionary equality treats
`False == 0` as true; this must **not** allow an SSA snapshot with `may_block=0`
to masquerade as the checked `may_block=false` contract (or `heap_allocations=false`
as integer zero). A resealed scalar SSA also must retain the exact known set
of conservative proof-claim flags. Negative tests cover both type confusions,
missing fields, and forged proof-flag elevations.
