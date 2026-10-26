# P0–P7: checked-source resource authority integrated into the native path

**Current implementation checkpoint, 2026-10-25.** This document is an
implementation/acceptance boundary, **not** a claim that every P0–P7
production blocker has closed.

## Exact integration ancestry

- Parent PR #141: `0243e0f5d96fd830e0242902a8fc1d2db3bfff68`
  (resource CFG reachability, stronger ELF/COFF object binding).
- Independent donor PR #142:
  `df7220d79e700c8e88420ef94f5dd0b971efe07a`
  (finite static resource policy requires `checked.ok is True`, rejects
  contradictory `may_suspend=false` claims).
- Common predecessor: `daf3f51fca6a441834c5cf9fdae5cdf26558d28e`.
- Five donor files were merged through exact Git blob identity only where
  the parent was unchanged relative to the predecessor. Stronger #141 native
  symbol parsing and unreachable-owner CFG rejection remain authoritative.
- Source native Resource IR gate: this follow-on implementation reuses
  `hepta.semantic_ir`, `hepta.resource_lowering` and `hepta.resource_ir`.
  It does not introduce an alternative checker, source IR, or native backend.

## New P1/P5 mandatory native acceptance

The strict `build_llvm_ssa_source` must perform, **before Clang invocation**:

1. A successful actual Rust reference validation and checked Hepta project
   with stable import graph identity.
2. Scalar adapter production from the **sole** checked canonical HSIR encoder.
3. Re-derivation of the checked canonical source with exact SHA matching the
   already-produced scalar adapter's `source_semantic_sha256`.
4. Re-lowering of an abstract owner/loan Resource IR from the **same**
   `(program, checked)` and explicit `project.identity`; no incoming
   caller-provided resource JSON is trusted.
5. Independent resource CFG verification, with all known blocks reachable,
   zero foreign obligations, exact source/digest/function inventories and all
   proof statuses remaining explicitly false.
6. An exact closed receipt schema and **identity-checked bool literals**;
   claim additions, `True`/1 substitutions and source/resource hash mismatch
   reject before native LLVM emission.
7. Original strict CFG→SSA→LLVM origin and object-symbol checks, native staging,
   no-overwrite publication, exact-byte post-publication replay, and source
   graph recheck remain unchanged.

Both positive and negative source tests are committed in
`tests/test_native_resource_gate.py`. The original native CLI success test
also asserts the new mandatory checked-source graph identity and **never**
elevates `source_to_resource_ir_refinement_proved` or
`whole_language_memory_safety_proved`.

### Qualification commands (not CI dependency)

```sh
python -m unittest tests.test_native_resource_gate \
    tests.test_llvm_ssa_cli tests.test_static_resource_policy \
    tests.test_static_resource_lowering tests.test_resource_ir \
    tests.test_resource_source -v
```

Run on an actual checkout of the **final SHA** with pinned rustc and Clang when
available. The full integrated native acceptance has **not** run in this
interaction. Earlier 46-gate report remains bound exclusively to
`2f8cd75d5ab5dba08f130561c1b9198c76e6ba6e`
(1,369 tests passed, 44/46 complete gates passed, two LLVM measurement
stability failures). Do **not** borrow those receipts for this code.

## Explicit non-closure (remaining P0–P7)

| Stage | Subset implemented | Outstanding blocker |
| --- | --- | --- |
| P0 | One canonical source semantic authority, exact source/provenance | Formal whole-compiler/source semantic refinement not proved |
| P1 | Typed resource static clauses, stored loans and independent CFG, mandatory scalar native gate | General loans+traits/lifetimes, full pointer provenance, combined concurrency soundness |
| P2 | Clang compilation DB, real chosen C projects | General arbitrary-source C equivalence, safe ownership reconstruction |
| P3 | Linux and finite Windows C ABI, strict native export parsing | Multi-host C++ ABI, MSVC/ARM physical bidirectional execution |
| P4 | Narrow C++ scalar and exclusive byte-owner migration, bridges | Arbitrary nontrivial RAII/STL/exception/template migration and maintained upstream equivalence |
| P5 | Finite scalar and owned LLVM paths plus source replay and publication | Whole-language backend parity, source/backend refinement and stable independent performance |
| P6 | Pinned Agent workspace with contract and crash checks | Actual controlled model 2×2, independent real-service operating cost/behavior |
| P7 | Linux/Windows limited execution, QEMU models | Physical boards, DMA, GPU/NPU, long-running production resource and recovery evidence |

A source-bound independent resource graph is an abstract check, **not** a
proof that the checker/lowering/model are sound for every input, and the LLVM
compiler still does not consume this graph as executable machine IR.
`whole_project_blockers_closed=false`.
