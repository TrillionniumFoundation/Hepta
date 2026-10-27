# HIA P0: refuse hidden schema/profile rebinding

## Exact development boundary

- Base: PR #210, commit `cf36bd112070bdb77dd70d9566455d9657c862a4`.
- This is a **narrow P0 audit hardening**, not the introduction of another
  verifier, a new HIA dialect, or a claim that P0–P7 are closed.
- Existing owner: `tools/audit_hia_schema_collision.py`. The runtime executable
  admission authority remains `hepta.hia_program.verify_program`; the
  version registry remains `hepta.hia_schema`.

## Fixed false-negative classes

The audit previously parsed literal top-level `SCHEMA`/`PROFILE` assignments
but could return `no_profile_collision_detected_not_semantic_equivalence` after
a module contained a later conditional assignment, loop target, import alias,
exception/match binding, namespace redefinition, or dynamic `globals()`/`exec()` operation capable of replacing one of those names.

It now rejects noncanonical AST bindings, including nested stores/deletes and
common dynamic-reflection entry points, rather than claiming an audit of
a mutable semantic declaration. The unchanged default remains strict: a
literal source constant and its matching profile must both be present.

The separate `compare` boundary also validates exact inventory keys, SHA-256
hex shape, schema/profile entry structure, and unique declaration/schema
keys. Duplicate inventory rows can no longer be silently collapsed by the
comparison dictionary. A correctly shaped SHA-256 string is **not** proof that
the supplied JSON originated from the named source file.

## Tests and exact scope

```sh
python -m unittest tests.test_hia_schema_collision \
  tests.test_hia_schema_binding_audit -v
python -m unittest tests.test_hia_schema_unification \
  tests.test_hia_core_upgrade -v
```

The self-contained AST/inventory logic and positive/negative controls were
exercised independently under CPython 3.13 (4 isolated test methods passed).
This was **not** execution of the exact new Git tree's complete Hepta suite:
the local environment cannot resolve GitHub for a full checkout. The
committed regression module must run with the pinned complete repository.

This syntactic audit is deliberately not a trusted-runtime evaluator. It
does not prove the absence of arbitrary dynamic Python module mutation,
that distinct source producers are semantically equivalent, or that an
HIA ABI/backend or C/C++ migration is safe. Neither `safe_to_merge` nor
`whole_project_blockers_closed` becomes true as a result.

## Next P0–P7 dependencies

P0 still requires all producer/consumer wire adapters (especially the
historical HSIR collisions) to be reconciled against exact source blobs.
P1 remains general Provenance/Memory SSA plus complete ownership effects.
P2 requires executable Core-to-Rust/LLVM refinement and error-path
differential; P3/P4 need live ABI and full C/C++ L2–L3 migration evidence.
P5 remains actual held-out model A/B with cost/error controls.
P6 still requires physical hardware and stable representative performance.
P7 requires machine-checked scoped refinement and production qualification.
CI queueing does not change these semantic acceptance conditions.
