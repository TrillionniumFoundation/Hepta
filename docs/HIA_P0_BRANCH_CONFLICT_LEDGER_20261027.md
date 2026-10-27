# P0 exact-blob branch conflict inventory — Hepta HIA v7 vs full native integration

## Identity and method

- Competing implementation PR #115: `4ac39e626acd7f78e2f66708be741e78308b4e6a`, Git tree `99a2273d45a333a1a9cc87110742399e7413d512`.
- Current standalone HIA v7 convergence PR #286 (before this evidence-only commit):
  `07f9490ec896a43328ac49339320f03a60a8bb0b`, Git tree `9ef7908558ac6b1ad45cd8fe68784b82d8c7af63`.
- Both inventories were retrieved as recursive immutable Git trees. This is
  a **Git object/path overlap audit** only, not a semantic parser,
  safe merge algorithm, native test run or cross-branch proof.

## Exact counts

| Metric | Observed paths |
| --- | ---: |
| PR #115 regular-file blobs | 3020 |
| PR #286 regular-file blobs | 2828 |
| Same path on both | 2675 |
| Same path **and identical Git blob** | 2615 |
| Same path but different Git blob | **60** |
| Only in PR #115 | 345 |
| Only in PR #286 | 153 |
| Compiler/ISA-related conflicting paths, including tests | **32** |

The complete exact-SHA inventory is in
`evidence/integration/hia-p0-branch-blob-inventory-20261027.json`.
A Git Blob comparison establishes byte identity or difference only; it
**does not establish semantic equivalence or the safety of overwriting one
implementation with another**.

## High-risk overlapping compiler and test paths

| File | #115 blob prefix | #286 blob prefix |
| --- | --- | --- |
| `hepta/backend.py` | `21d89f935630` | `899292efc43b` |
| `hepta/c_backend.py` | `2784c07eb381` | `8559838ce657` |
| `hepta/c_migrate.py` | `3e803c1c7ad1` | `ffcf6817db47` |
| `hepta/c_migration_project.py` | `82662b99dba0` | `4edec696b2d9` |
| `hepta/c_record_views.py` | `dcb1dd081765` | `7247899c5514` |
| `hepta/c_translation.py` | `a502a92641e2` | `7f7ecf796040` |
| `hepta/checker.py` | `e954a11e12ae` | `e12368e93529` |
| `hepta/cli.py` | `0c924c7f1325` | `09088103a68a` |
| `hepta/cpp_contracts.py` | `daaf70a3618f` | `5a4c2185e4b3` |
| `hepta/elf_shared_abi.py` | `3493cc86d9ed` | `b334960b7d09` |
| `hepta/hia_bounded_memory.py` | `ee7006b87992` | `35deffb3582a` |
| `hepta/hia_core_upgrade.py` | `4ef6600c729d` | `9a401b8ed837` |
| `hepta/hia_edit_query.py` | `1c1bbeb0a91a` | `cc155d8bb7ba` |
| `hepta/hia_migrate.py` | `8fc5383e0c3f` | `5bba30e5ea17` |
| `hepta/hia_program.py` | `881a7c0a6bff` | `13b14c8c1361` |
| `hepta/hia_program_composite.py` | `feccc45c93ea` | `622f2832be06` |
| `hepta/hia_program_llvm.py` | `878695452c02` | `f9aa68975dd9` |
| `hepta/hia_program_runtime.py` | `84224a9d2567` | `95d6fcd81be5` |
| `hepta/hia_schema.py` | `a26a7cd600a0` | `64ce2258f5c0` |
| `hepta/hia_source_bridge.py` | `4ce072c8d472` | `09188439513e` |
| `hepta/llvm_owned_backend.py` | `57b126800b0a` | `c46b009775e7` |
| `hepta/runtime_concurrency.py` | `13a0a0363942` | `d12af1d6bf56` |
| `hepta/runtime_io.py` | `f00f33881be3` | `841df2ee9b9f` |
| `hepta/runtime_task_tree.py` | `c733c49abe0a` | `c4ffb6606f95` |
| `tests/test_hia_cli_seven_stage.py` | `6c59c4c74378` | `ba5dfc5f82ae` |
| `tests/test_hia_composite_bulk_native.py` | `5969327ff582` | `fbeeced16feb` |
| `tests/test_hia_core_upgrade.py` | `56690627c299` | `7f623f2f231a` |
| `tests/test_hia_edit_study.py` | `5861d39c6935` | `8699837c8c40` |
| `tests/test_hia_migrate.py` | `5032ed848ee3` | `f0349d540111` |
| `tests/test_hia_program_llvm.py` | `440791fc3132` | `f15caed4171f` |
| `tests/test_hia_unified_qualification.py` | `f230346e51bb` | `9ccf7620a518` |
| `tools/audit_hia_schema_collision.py` | `306714ddc703` | `0e08029df534` |

## Explicit integration policy

1. Freeze both exact source heads. Never treat a mutable PR name or an
   historical SHA as the current integration source after either moves.
2. Preserve unique implementation modules on both sides until reviewed;
   PR #115 uniquely has `cpp_composed_migrate`,
   `native_local_views`, and `runtime_task_io`; the v7 stack uniquely
   has `hia_static_budget`, `hia_heap_bound`,
   `hia_json_preflight`, batch HIA edits and Rust shadow modules.
3. For each conflicting compiler/ABI/ISA authority, decide a single
   versioned producer, verification owner, adapter and consumer. Detect and
   reject rather than coerce historical v2 schemas with different meanings.
4. Reconcile actual resource/borrow/ABI/native lowering code using reviewed
   semantic diffs and adversarial tests, **not just path order or recency**.
5. Require source→Core→independent/native differential evidence bound to
   a fresh combined HEAD; keep full-qualification unknown until executed.
6. Do not auto-merge or delete either donor branch based on this audit.

No attempt is made to declare P0 closed merely because exact-file evidence
has been collected. General Memory/Provenance SSA, C/C++ L2–L3,
source/backend refinement, AI held-out evaluation, real hardware and
production/p99 blockers remain OPEN. `whole_project_blockers_closed=false`.
