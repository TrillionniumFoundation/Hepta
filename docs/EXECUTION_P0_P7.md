# Hepta P0–P7 execution and acceptance contract

Status: **incremental engineering branch**, not a release. The original production blockers P01–P12 remain open until source-matched native, platform and safety evidence closes them. See [BLOCKERS](BLOCKERS.md) and [IMPLEMENTATION_P0_P7](IMPLEMENTATION_P0_P7.md) for the pre-existing implementation ledger.

## Source baselines and reproducibility

- Frozen main: 48600e3126f7ddf930ed4006476dd01d7a92e473.
- Started from PR #1 development SHA b38a9f73ad28f44a44c11666ac2f9a006106f842.
- Historical Hepta 0.2: 393 tests / 13 gates passed on its recorded source snapshot; this is not fresh qualification of this branch.
- PR #1 run 40102156959 was **cancelled**, not passed. Repeated pushes combined with one shared concurrency group and cancellation prevented that snapshot from receiving an uninterrupted run.
- This branch assigns full-gate runs an exact source SHA concurrency key and disables cancellation of earlier snapshots. On completed checks, inspect the SHA-bound logs and hashes before closing P0.
- The new Python-only smoke tests are not substitutes for pinned Rust 1.90.0, GCC, Clang, Lean and QEMU qualification.

Reproduce on an environment with the pinned native toolchains:

    python -m unittest discover -s tests -v
    python -m hepta hmir /path/to/scalar.hepta --frontend-only
    python tools/release_check.py

**Frontend-only does not mean native borrow checking passed.**

## Delivered: HMIR scalar CFG / SSA pilot

The hepta/hmir.py module exports schema hepta.hmir.cfg-ssa.v0 for a *deliberately restricted* subset that has first passed the existing type/effect/resource checker.

- Basic blocks, return/jump/branch terminators, predecessor records.
- If/else and while control flow with Phi nodes and loop backedges.
- Deterministic SSA definitions, canonical digest, source hash and project identity.
- A separate validator checking reachability, edge/predecessor agreement, unique SSA definitions, Phi predecessor arity, and dominance of SSA reads.
- Read-only typed expressions retain evaluation structure. **No codegen or VM consumes this IR.**
- Only by-value scalars with empty or panic effect are accepted; resources, generic/extern/export declarations, borrowed values, unsafe code, memory writes, function calls, match/for, lexical nested locals and other unmodeled cases fail closed.
- A JSON rejection carries E_HMIR_UNSUPPORTED. Internal verifier failures also reject.
- Claims explicitly deny Move/Borrow/Drop proofs, pointer provenance safety, native borrow validation, lowering correctness or whole-language safety.
- CLI input: hepta hmir input.hepta --frontend-only. The output status is frontend_only, not a native pass.

This is **P1 PARTIAL**, not an independent Rust-level safety checker.

## Actual P0–P7 closure gates

| Stage | Current status | Required qualification |
| --- | --- | --- |
| P0 — stable baseline | PARTIAL: historical 0.2 evidence; fresh PR #1 head required | Final exact commit passes all 13 gates, all negative controls, source hashes, ABI and review; queue/cancel is not pass |
| P1 — HSIR / HMIR | PARTIAL: typed AST interchange and scalar CFG/SSA | Complete CFG, lexical storage, Move/Borrow/Drop, effect and memory SSA, provenance, independent safety checks and source→MIR→Rust differential validation |
| P2 — compiler in Rust | OPEN: current compiler in Python | Rust parser/checker/lowerer matches Python positive/negative corpus and diagnostics, outputs are deterministic and native verification is not bypassed |
| P3 — C migration | PARTIAL: Clang scalar migration pilot in PR #1 | Real C code: pointer+length, arrays/structs/loops, allocator and cross-call lifetimes, ABI, behavior and secure migration classification |
| P4 — C++ ecosystem | PARTIAL: simple scalar opaque-handle bridge in PR #1 | Multiple real libraries covering templates, destructors, exceptions, dynamic dispatch, target ABIs and lifetime obligations |
| P5 — Agent Native | PARTIAL: patch v2 and v3 preview | Typed holes, proof obligations, durable multi-file patch transactions and real-provider Agent A/B completion/quality/cost |
| P6 — direct native | OPEN: no LLVM pipeline yet | LLVM lowering tests, debug fidelity, sanitizer runs, CPU/OS cross-target qualification and representative performance comparisons |
| P7 — self hosting | OPEN | A Hepta compiler core builds its next generation reproducibly with cross-generation comparisons and independently qualified artifacts |

Physical embedded hardware, DMA/MMIO, GPU, native Windows/ARM ABI and long-running workload evidence remain separate blockers. Closing P0–P7 does not override the old P01–P12 ledger.

## P1 proof obligations

1. Define operational semantics for source AST and MIR, plus Rust/LLVM refinement rules including panic and cleanup.
2. Model lexical storage identity, borrow exclusivity, move/drop, aliasing, pointer provenance and allocator ownership on every CFG edge.
3. Make destructors and scoped cleanup explicit for returns, loops, branches and exceptional exits.
4. Verify all Phi/SSA properties with randomized and negative tests, and extend to memory/effects.
5. Build a differential interpreter and check it against actual Rust codegen with seeded generated programs and minimized counterexamples.
6. Keep C/C++ FFI contracts as external obligations; generated bindings and passing tests do not prove foreign implementation safety.
7. Require real platform execution and independent review before asserting hardware compatibility or performance parity.

Each gate must distinguish passed, failed, unsupported, not_run, and environment_blocked with the corresponding source SHA, exact toolchain and evidence. **whole_project_blockers_closed remains false** until every production and stage obligation is qualified.
