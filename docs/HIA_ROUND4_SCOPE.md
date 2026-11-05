# Round 4: one frozen implementation and explicit research boundaries

This round integrates concrete correctness fixes and one real HIA dynamic
workload. A source commit is frozen before qualification. Later evidence
packaging is a separate commit and never substitutes its identity for the
measured source. Component experiments from other commits remain component
experiments; they cannot complete a missing gate on the integrated commit.

## Fixed composition

The existing [composition qualifier](../tools/qualify_hia_composition.py)
retains its 36 commands and 34 qualification flags. Its source identity checks
the committed tree, complete Git status, and every materialized active source
against its Git blob. Tool identities include Clang 20, Rust 1.95.0, the separate
Rust 1.90.0 source-reference toolchain, Lean 4.19.0 and Z3 4.15.4. The NDU upstream
pin and distinct bridge protocols remain explicit. A positive experiment exit
does not imply positive cost or performance results.

The [frozen sequence observer](../experiments/hia_round4_20261105/run_frozen_candidate.py)
requires an explicit expected commit. It runs a fresh complete eleven-stage
syntax qualification within the existing 600-second budget, then a separate
full evidence replay with its existing 600-second budget. Only their actual
successful receipts authorize the unchanged composition observer. Each step
checks the same source and tools before and after execution. No failed stage
is retried by this observer. A failed full command remains failed even if an
inner result file says passed.

The result-cache extension uses its own registered native planning bridge and
must report that bridge's build and protocol separately. A fresh extension run
must use the same integrated source and explicit tool identities; an old
binary's successful pilot does not close the new composition.

## Implemented changes and what they establish

| Area | Concrete increment | Remaining closure condition |
| --- | --- | --- |
| Unified composition | Restored exact historical dependencies; retained upstream literal source indexing; added terminal, PHI and cache regression modules to the actual suite | Fresh full proof, replay and complete composition receipts must all name one commit |
| Sequential Safe Core | Reject invalid PHI incoming definitions on every CFG edge, including untaken edges; preserve edge multiplicity; bind PHI outputs simultaneously | General language soundness, ownership-to-native refinement, and the twelve wider initialization obligations remain open |
| Capture and exit semantics | Check process and cleanup deadlines after actual reads and exit/reap observations; never renew cleanup after an exception | These finite real-child controls do not establish a real-time scheduler or OS theorem |
| Strong AOT | Preserve the existing baseline; retain a range-prefix optimization as an explicitly failed candidate | Original Rust median, p95, p99, cold-call and resource gates must all pass on a fixed workload |
| Real HIA dynamics | Compile HIA source through verified Core and LLVM into a sealed native executor; use exact-key bounded cached results, invalidation and preparation-aware planner admission | NDU must beat strong fixed and lightweight policies with the same information, candidates and executor after all costs |
| C/C++ migration | Keep full existing resource, callback, upstream-upgrade and native-port lanes in the same composition | Broader whole-module/build-configuration coverage and observed human upgrade effort are not implied by finite controls |
| Agent productivity | Preserve full language-by-editing-tool records and tooling controls; add symmetric public editing-contract feedback while retaining the exact admission rule | Independent maintenance tasks need complete successes and matched full-success cost; zero-success cells cannot prove an advantage |
| Concurrency and hardware | Keep actual host-region lifecycle and recovery-race qualification | Atomics, async, DMA, device and GPU semantics each need their own real implementation, failure recovery and hardware evidence |

See [the sequential proof chain](HIA_SEQUENTIAL_CORE_PROOF_CHAIN.md),
[PHI edge checks](HIA_SCALAR_PHI_EDGES.md),
[terminal deadlines](HIA_CAPTURE_TERMINAL_DEADLINE.md), and
[the HIA result-cache protocol](../benchmarks/hia_result_cache/PROTOCOL.json).

## Evidence accounting

All observed failures, including control-fixture corrections and shared-host
short-deadline failures, are retained with their exact source and observer
identities. Subsequent diagnostic runs do not change an earlier result. The
fixed historical CI counts of 207 and 705 are retained; new modules have
additional explicit controls.

Outer wall time includes nested child time. These clocks are not added twice.
Build, load, calibration, preparation, invalidation, planning, execution,
verification, residency and observation costs are stated where measured.
Unobserved human effort, energy and historical acquisition costs remain null
or unknown. The desktop is shared and CPU affinity is not host exclusivity.

The source's authority remains `DENY_ALL`; no safety certificate, production
admission, broad migration claim, general Agent advantage, or seven-target
closure is created by this research round.
