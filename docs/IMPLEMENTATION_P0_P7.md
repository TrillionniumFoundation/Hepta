# Hepta P0–P7 execution ledger (2026-10-24)

This document separates **implemented increments**, **historical release
evidence**, and **still-open production qualification**. Neither a successful
frontend pass nor a generated bridge is a proof of language-wide memory safety,
semantic equivalence, Rust performance parity, or trustworthy foreign code.

## P0: immutable starting point

- Repository: TrillionniumFoundation/Hepta
- Frozen upstream main commit: 48600e3126f7ddf930ed4006476dd01d7a92e473
- Hepta 0.2 release commit: 367c6c31fc592a9f78df78fdcad5a4dd58792e1e
- Hepta 0.2 published source snapshot SHA-256:
  0b7a747bd732cea30d2e914c7080ac58086e11eca4fec44b0592d4b23d1b772f
- Published release result: 13 prototype gates, 393 tests with zero skips.
  This is **historical evidence**, not a fresh execution in the current branch.
- New workflow: .github/workflows/hepta-qualification.yml. It installs
  SHA-256-locked Rust 1.90.0, Lean 4.19.0 and QEMU, then runs
  tools/release_check.py and preserves logs/evidence.
- The current execution host lacks local rustc and cannot clone GitHub through
  its network namespace. A queued remote workflow is **not a passed run**.
  Only a completed, source-matched report may close the P0 re-run gate.

## Current branch deliverables by dependency stage

| Stage | Implemented increment | Completion status and remaining acceptance |
|---|---|---|
| P0 | Exact release provenance and a pinned full-gate workflow | PARTIAL: branch rerun needs completed logs and receipts |
| P1 | hepta.hsir.v0 deterministic typed-AST interchange; project identity, inferred/declared effects, resources, spans, explicit unknowns and foreign obligations | PARTIAL: no independent optimizer MIR, lifetime/alias proof, resource-carrying ADTs or lowering proof |
| P2 | C target-size facts in Clang-based migration; original 0.2 host C ABI remains reference | PARTIAL: Windows/ARM64 C/C++ real-host ABI tests and hardware models still required |
| P3 | hepta migrate-c: strict Clang-AST scalar function subset, host model, whole-input rejection, frontend checks and native differential-test harness | PARTIAL: pointer ownership, globals, aggregates, macros, headers, C projects, cross-target qualification open |
| P4 | hepta bridge-cpp: public non-template class with explicit zero-arg ctor/dtor and scalar methods; exception status mapping; mutex-protected opaque integer handles and stale-handle rejection | PARTIAL: C++ templates, inheritance, virtual dispatch, overloading, nontrivial ABI layouts, callbacks, full exception guarantees and foreign internals not qualified |
| P5 | Conservative migration categories can be derived from P3/P4; no universal cpp2hepta converter | OPEN: Strict/Checked/Legacy safety-preserving source migration and performance parity not established |
| P6 | hepta.patch.v3.preview: 2–32 one-body changes across a checked project graph, frozen source/interface hashes, single native validation, no uncontrolled writeback | PARTIAL: durable journal, crash recovery, atomic multi-file readers, semantic IR optimizer, incremental compilation, proof checker still open |
| P7 | Existing 0.2 QEMU AArch64 and no_std objects; updated workflow retains historical gates | OPEN: physical ARM/x86/embedded/GPU, fault injection, representative workloads, tail latencies and long-run endurance |

## Security and evidence limits

1. HSIR v0 is not SSA, verified MIR, an independent borrow checker or proof.
   It carries explicit false soundness and translation-correctness claims.
2. C migration supports only scalar, pure, non-pointer integer logic and
   simple conditional returns. It preserves unsigned arithmetic wrap through
   dedicated wrapping operations. Signed C overflow is undefined, so aborting
   checked arithmetic only aims to preserve *defined* C input behavior.
   C integer promotions not proven safe are rejected.
3. C++ bridge objects remain native foreign code; handle-table checks protect
   only bridge-visible lifetimes. A foreign library may violate internal memory
   safety or data-race contracts; callouts/reentrancy may deadlock on the bridge
   mutex. FFI pointers to output storage remain caller obligations.
4. Patch v3 explicitly rejects apply. Sequential rename is not a crash-atomic
   multi-file transaction. Validation is still susceptible to noncooperative
   filesystem writers outside existing source-lock conventions.
5. No unsafe FFI boundary is promoted to a safe-language guarantee merely by
   successful compilation or tests. Provider/model coding efficiency runs are
   still absent.

## Reproduction commands

All commands below must be executed on a host with supported native compilers.

    python -m unittest discover -s tests -v
    python -m hepta hsir examples/results.hepta --frontend-only
    python -m hepta migrate-c path/to/source.c --output build/source.hepta
    python -m hepta bridge-cpp path/to/library.hpp --class Counter --output build/bridge.cpp --hepta-output build/bridge.hepta
    python tools/release_check.py

For P3 and P4, generated source must additionally be compiled and tested
against the original C/C++ implementation. The migration/bridge generators'
own reports deliberately do not claim execution when only syntax/frontend
checking occurred. The complete release gate is not replaceable by fixture
or host-only positive checks.

## Blocking dependency chain

P0 source/test/toolchain qualification -> P1 borrow/resource semantics and
verified IR -> P3/P4 source-preserving translation/interop (parallelizable
subsets) -> P5 sound safety classification and differential testing -> P6
durable change transactions/proof-carrying compilation -> P7 physical and
production-scale qualification.

Do not set whole_project_blockers_closed true until the original P01–P12
ledger has actual qualifying evidence for every item, and P0–P7 acceptance
here also has independent source-bound receipts.
