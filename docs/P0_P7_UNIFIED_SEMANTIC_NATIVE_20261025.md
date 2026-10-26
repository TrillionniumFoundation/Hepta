# P0–P7 unified semantic/native compiler integration checkpoint

Date: 2026-10-25. Status: **development candidate; production gates OPEN**.
This checkpoint makes progress without waiting for CI, but never promotes
historical evidence to the newly created integrated source SHA.

## Exact ancestry and one compiler authority

Base: PR #137 HEAD `8ae80897fa08adfa3608ad65b505387ac2dba997`,
which includes the unified checked Hepta source→owned Resource IR→LLVM
pipeline, C++ owner migration, published artifact validation and finite
resource effects. Common parent of PRs #136/#137:
`c483b4cedcc03a8bfcbe02d3c6b3f644f8c8af59`.

Donor PR #136: `54ee112ff842131f4a54cb6648a9f640a1a7d22a`.
A Git-tree audit compared the donor's eight *non-overlapping* paths against
both the common ancestor and #137; every destination was either absent in
both, or had the **identical original blob SHA**. Eight reviewed new blobs
were atomically transplanted in tree `9e7177f2c5c101fbe5f4a896e17e1fca4ae8ca35`
(commit `6004a7304fb0eeec6448c7bda98e9cc208973cd9`):

- `docs/P3_P5_UNIFIED_TARGET_OBJECT_SYMBOLS_20261025.md`
- `hepta/llvm_ssa_pipeline.py`; `hepta/llvm_ssa_target.py`
- `hepta/object_structure.py`; `hepta/object_symbols.py`
- `tests/test_llvm_ssa_cli.py`; `tests/test_llvm_ssa_target.py`
- `tests/test_object_executable_exports.py`

This imports **no competing language parser, canonical HSIR or owned LLVM
backend**. The sole checked semantic producer and typed scalar/owned IR
owner remain unchanged.

## Manual resolution of the two overlapping paths

PR #136 and #137 independently touched `hepta/llvm_owned_pipeline.py` and
`tests/test_llvm_owned_backend.py`. Do **not** transplant either donor blob:
it would silently discard #137's stronger byte/inode-bound
`artifact_publication.publish_verified` and its post-publication source
identity recheck. Retain #137 as the owner, and absorb the missing
post-publication attack control as a new regression.

The shared publication helper now exposes:

- `publish_verified(stage, destination, exact_bytes)`: no-replace hardlink
  with verified regular inode and exact byte identity.
- `verify_published(stage, destination, exact_bytes)`: independent replay
  *after* native source/project rechecking, before a successful receipt.
- `withdraw_own_link(stage, destination)`: retract only the published
  pathname still pointing to the current staging inode; preserve another
  writer's replacement.

Both `build_llvm_owned_source` and `build_llvm_ssa_source` use the same
publication owner, require exact SHA+size receipts and replay file identities
before success. If the final path changes or is corrupted after the publisher
returns, the origin build rejects and withdraws only its own link. The target
LLVM backend retains its previous internal object publication checks; all
outer source publication checks are now unified.

Do not overstate this guarantee: same-user adversaries may mutate files after
the check; point-in-time integrity is not malicious-writer isolation or
formal source-to-binary semantic equivalence. The generated native code and
external linker remain part of the trusted computing base.

## Direct executed tests on exact Git bytes, not CI

The exact `hepta/artifact_publication.py` code blob
`21129c16063ee5c2b317563da788c616399cffa7` and exact corresponding
`tests/test_artifact_publication.py` blob
`58f911f03755e5487151156bd1c05b9e8aad06a6`
were materialized to an isolated Linux Python 3.13.5 workspace. Local
`git hash-object` returned **those exact two SHA identities**.

Executed command:

    python -m unittest tests.test_artifact_publication tests.test_static_resource_policy -v
    python -m unittest tests.test_static_resource_lowering -v

Result: **15 tests passed, zero failures/skips**, including a real
Clang 17 compiled LLVM object and GCC-linked C caller execution (exit 0),
post-publication inode and content revalidation, symlink/FIFO refusal,
in-place corruption, no-overwrite, and competing pathname retention.

New full-Hepta native tests for scalar and owned source-facing pipelines
are committed, but were **not executed against the complete new branch
checkout**. Neither the old #115 44/46 qualification nor PR #136 isolated
cross-object data qualifies this unified source SHA. Rust1.90/Clang20/Lean/
real-model/board hardware results are not asserted here.

## P1/P5: static resource clause contradiction removed

The inherited #137 candidate allowed `heap_allocations=0`,
`may_block=false`, `may_spawn=false` and `may_suspend=false`
in `llvm_owned_backend._resources_allowed`, but its mandatory
`resource_lowering.lower_resource_ir` still rejected **every**
nonempty `fn.resources`. This made advertised safe source clauses
impossible to lower into the resource safety gate.

This candidate now uses exactly one pure
`hepta.static_resource_contracts.finite_static_contract_allowed`
for both consumers. Nonempty clauses are admitted ONLY for the four
reviewed, correctly typed finite values and when original declared
and transitive inferred effects satisfy the obligation; runtime
resource budgets and all unknown keys reject before Resource IR
generation. Legacy unconstrained functions retain their original
behavior. `llvm_owned_backend._resources_allowed` remains a thin
compatibility entrypoint, not a separate safety-policy authority.

Resource IR remains an abstract Ownership/Loan checker; the finite
contract check enforces source effect restrictions, not a global
memory/time bound, whole-language provenance proof or source-to-LLVM
refinement theorem. No new runtime accounting is claimed.

Independent exact-file verification:

- `hepta/static_resource_contracts.py` Git blob
  `68b3e4ef4ceabfbdeda05d81a760351609297667`
- `tests/test_static_resource_policy.py` Git blob
  `8032ab23c5aacca92b50042cbd5acd434aa58e65`

Local `git hash-object` confirmed both identities and Python 3.13.5
executed **12/12** policy tests without skips. Combined with the
15/15 previously verified publisher suite, the local exact-byte
result is **27/27 passed**. The separate committed
`tests/test_static_resource_lowering.py` runs real Hepta
checker/resource lowering/Owned LLVM integration and remains
**unexecuted** in this restricted local environment; it is
not counted in the 27 local tests.

## Current P0–P7 remaining work

| Stage | Increment on this branch | Remaining strict blocker |
| --- | --- | --- |
| P0 | Exact eight-blob integration; single canonical source/IR owner retained | Final complete source/consumer integration and full checked semantics |
| P1 | One typed source effect/resource predicate shared by Resource IR and Owned LLVM; invalid zero-cost clauses reject | General Borrow/Drop/Provenance refinement and whole-language typing soundness |
| P2 | No change to pinned Rust reference, frontend | Independent Rust compiler implementation and fully differential validation |
| P3 | Five-target object symbol import/export containment integrated | C full multi-TU pointer migration and actual cross-host C ABI execution |
| P4 | #137's C++ migration and publication guards retained | General RAII/STL/templates, MSVC/Itanium ABI and larger real C++ projects |
| P5 | Scalar/owned native source paths share strict final publication authority and the same finite static resource policy | Full end-to-end semantics, stable representative performance, actual native matrix |
| P6 | Existing Agent contracts retained | Real model controlled A/B and durable multi-file fault/recovery execution |
| P7 | No board/GPU code claim | Physical DMA/MMIO/IRQ/GPU/NPU execution and sustained-resource qualification |

Keep `whole_project_blockers_closed=false`. Do not merge to main or upgrade
production claims without exact-source proof and tests.

## Reproduce

    python -m unittest tests.test_artifact_publication -v
    python -m unittest tests.test_object_executable_exports tests.test_llvm_ssa_target -v
    python -m unittest tests.test_llvm_ssa_cli tests.test_llvm_owned_backend -v
    python -m unittest discover -s tests -v

No step may silently downgrade to frontend-only or skip unsupported target
semantics while claiming a native full qualification.
