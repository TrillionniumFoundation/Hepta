# P0/P1/P3/P5 unified next increment — source-bound resource policy

Date: 2026-10-25. Base is PR #139 exact source head
`daf3f51fca6a441834c5cf9fdae5cdf26558d28e`.
Working branch: `agent/hepta-p1-unified-safe-core-20261025`.

This is an incremental engineering/security patch. It **does not** close all
P0–P7 production blockers. Nothing here downgrades borrow/drop/provenance
checks or claims the full Hepta native compiler is formally sound.

## P0/P3/P5: exact donor integration

The donor PR #140 exact head is
`915b9b53ca7741299d31cde5c24580985d99eee1`.
The following **unchanged Git blobs** were inserted in one Git tree and
one fast-forward commit after confirming #139 had the donor's exact reviewed
parent blobs:

| Path | Imported donor Git blob SHA |
| --- | --- |
| `hepta/object_symbols.py` | `3a08491cc38f5340afd7215ed89cf92a2e8b708c` |
| `tests/test_object_executable_exports.py` | `b3acf662915a59296605279163a9c9b5b9a84ed0` |
| `docs/P3_P5_DEFINED_GLOBAL_EXPORT_AUDIT_20261025.md` | `32884c4aea94895b5786ba3d8ee6323e45bc4283` |

All compiler paths continue to use the single existing
`hepta.object_symbols` authority. This import preserves public
data/global-export and ELF GNU-unique refusals on top of #139's
shared scalar/Owned LLVM artifact publication and static source contracts.
PR #140's direct five-target Clang experiments belong to **its own tested
SHA** and are not claimed as a full test run of this integrated HEAD.

## P1/P5: a real static resource proof-admission hole

The same `finite_static_contract_allowed` predicate is consumed by
`resource_lowering.lower_resource_ir` and
`llvm_owned_backend._resources_allowed`. No second evaluator was added.

Two cases could previously be marked admissible:

1. A stand-alone caller supplied a plausible, pure `checked.effects`
   dictionary but omitted `checked.ok`. The source might have diagnostics;
   a fabricated effect table must not qualify a zero-cost resource claim.
   The finite predicate now requires literal `checked.ok is True`.
   This is a necessary condition, **not** independent checker authenticity.
2. `may_suspend=false` checked only for an inferred `suspend` effect.
   The source checker currently has **no `suspend` entry** in its closed
   effect vocabulary. Therefore the old predicate incorrectly admitted
   `block` and `spawn`, despite not being able to establish their
   non-suspending behavior. The finite native profile now rejects these
   ambiguous effects whenever `may_suspend=false` is asserted.

The unconstrained legacy profile (`resources={}`) still admits ordinary
known effects; no fictitious global CPU/memory budget was introduced. Other
finite `heap_allocations=0`, `may_block=false`, `may_spawn=false`
checks retain their exact-value and transitive-effect conditions.
`ffi`, `unsafe`, `io` still prevent nonempty cost contracts.

## Direct executable evidence — no CI dependency

Using Linux Python 3.13.5 with an exact minimal `checker.EFFECTS`
mirror of the checked language's actual set:

- Reconstructed old policy and verified its Git blob as
  `6663d1dd27c0c2e0766a5dcf37f5daf35cefbc4c`.
- Reconstructed the **new** policy and verified its Git blob as
  `346ccb0308d9bbf9bbb699112ff880abb30a4f0d`.
- Before patch: both 'unchecked effect metadata with no successful checker'
  and 'blocking function claiming may_suspend=false' returned True.
- After patch: both return False; 9/9 locally exercised
  positive/adversarial policy cases passed.
- Executed the complete **15/15 isolated source-file unit tests**, no skips,
  on Python 3.13.5 using the exact new module and test source blobs
  `346ccb0308d9bbf9bbb699112ff880abb30a4f0d` and
  `f8b2cc5ebb04c441983dfb7b7003d16d0f39a330`. The only local
  substitution was a one-line checker.EFFECTS vocabulary stub copied
  exactly from the pinned real frontend; no Hepta end-to-end execution
  or pinned Rust borrow validation is implied.

Committed tests additionally cover the shared predicate, its use from
both Resource IR and Owned LLVM, malformed booleans, blocking/spawning,
real `CheckResult.ok` false and safe legacy unconstrained functions.
**The full repository integration suites on this final branch head
have not been run in this isolated local environment.**

## Exact-source reproduction

    python -m unittest tests.test_static_resource_policy tests.test_static_resource_lowering -v
    python -m unittest tests.test_llvm_owned_backend tests.test_resource_ir -v

Keep source Git identities and failure output bound to one exact HEAD; neither
these tests nor a compiled ABI object prove whole-language soundness.

## Remaining P0–P7 blockers

| Stage | What changed here | Still open |
| --- | --- | --- |
| P0 | Single canonical source semantic pipeline preserved; exact no-conflict donor integration | Complete candidate/branch integration, whole-repo final-HEAD qualification |
| P1 | Unchecked/ambiguous zero-cost proofs rejected by single shared evaluator | General Ownership/Borrow/Drop/Provenance soundness and source→resource→backend refinement |
| P2 | No compiler-core port in this patch | Independent Rust core, differential validation and stable portable reproducibility |
| P3 | Object exports now reject unapproved public/unique globals | Full multi-TU C pointer migration and independent ABI execution across physical hosts |
| P4 | Existing C++ bridge/migrator untouched | General classes/RAII/templates/STL migration, actual MSVC/C++ ABI contracts |
| P5 | Existing shared scalar and Owned LLVM source/object publisher retained | Full semantics/optimization, representative workload performance stability |
| P6 | No Agent schema change | Real controlled model A/B and durable multi-file transactional behavior |
| P7 | No hardware claim | Board DMA/MMIO/IRQ, GPU/NPU, sustained real hardware fault injection |

`whole_project_blockers_closed=false` is mandatory.
