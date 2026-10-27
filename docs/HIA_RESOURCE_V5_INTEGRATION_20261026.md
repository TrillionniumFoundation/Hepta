# HIA Scalar Core + Resource IR v5 integrated acceptance

Integration parent: PR #163 exact commit `2322e2d9479850dd0e0adbe8534cb31089e5547d`.
Resource-v5 input: PR #162 exact commit `2a72dde6f46b113fafe3099385dde371bdff76ae`.
First composite commit: `a3b1edcede35ed58db3de7685f210c5fdd1455b9`.
Tree: `ba58179ffd8058f78175b92343ab85d0de7d6044`.

The integrated source preserves existing HIA scalar verifier/oracle and the
independent Resource IR v5 stored-u8-loan Copy label update profile. Exactly
six source/docs/test blob identities came unchanged from PR #162. All six
paths were identical to the PR #159 common ancestor on PR #163, or absent
(new example), so this transplant has no file-object overwrite conflict.

No CI result is a prerequisite to continuing development. But none of the
historical native receipts counts as a pass on this composite tree.

## Exact-source first qualification

Run in a full checkout with the pinned project toolchain:

```sh
python -m unittest tests.test_resource_views tests.test_hia_core tests.test_hia_oracle -v
python -m unittest tests.test_native_resource_gate tests.test_llvm_ssa_cli tests.test_llvm_ssa_origin -v
python -m hepta resource-ir examples/resource_views/labelled_view.hepta
python -m hepta run examples/resource_views/labelled_view.hepta --json
```

An actual combined runtime fixture should also exercise the new mutable
Copy label alongside a shared borrowed slice, verify that the loan never
upgrades to a mutable loan, verify the owner's release after ending the
view, and reject a forged v4 schema downgrade.

## Status

- **P0**: source-bound single canonical semantic authority exists in the
  bounded pipeline; whole compiler source-to-IR soundness OPEN.
- **P1**: local typed Copy fields and label updates in Resource IR v5 now
  join the HIA candidate; interprocedural loans, full lifetimes/provenance and
  source/backend refinement OPEN.
- **P2**: executable scalar i32/u32 HIA oracle integrated; HIA v1 owned/
  borrowed value/place memory-token SSA and general native refinement OPEN.
- **P3**: C/ABI bounded captures and host execution are partial; independent
  target/compiler combinations require real qualification.
- **P4**: selected C++ class and finite owner migration remain bounded; general
  resource-owning RAII/templates/exceptions unsupported.
- **P5**: finite LLVM Owned path and ARM64 object/link/runtime exist on parent
  branches; general HIA-owned-codegen lowering and independent proof OPEN.
- **P6**: structured Agent workspace and receipts exist; real independent
  live-model A/B and resource/cost effectiveness remain OPEN.
- **P7**: simulator/runtime evidence does not close physical board, DMA,
  IRQ, GPU/NPU, long-running service and recovery targets.

`whole_project_blockers_closed=false`. This integration is not a production
release or a claim that the HIA scalar execution oracle models Resource IR
v5 instructions.
