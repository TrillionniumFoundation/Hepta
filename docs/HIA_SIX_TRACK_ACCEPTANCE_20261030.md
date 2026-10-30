# Six-track acceptance ledger — 2026-10-30

This is a post-execution acceptance record. The implementation is partially
qualified; the original full-language, Rust-class safety/performance, general
C/C++ migration, global optimization and physical-device goals remain open.
The machine-readable record is
[`ACCEPTANCE.json`](../evidence/hia_six_track_final_20261030/ACCEPTANCE.json).

## Source and execution identity

The latest implementation source is
`91ac6008fc5d67acb8354383f7006d9d899f54f3`, executed in
[run 41063003872](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41063003872).
All three jobs in that six-track workflow passed. The preceding source
`03c8205271dc5e8f9c5cad806e46056bffe2bc02` and
[run 41059492139](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41059492139)
are preserved as separate observations. Their workloads overlap; this is not
new-task generalization evidence. All six workflows for the exact latest source
completed successfully and were independently read back. The full inventory
and timestamps are in
[`CI_STATUS.json`](../evidence/hia_six_track_final_20261030/CI_STATUS.json).
This CI result does not change any broad user-acceptance flag.

This document and ledger belong on a separate evidence branch. Their later
publication commit must never replace the source SHA attached to an execution.
Artifact links, upload-verified archive digests and report hashes are in the ledger.

## Delivered work and remaining acceptance

| Track | Delivered and observed | Still open |
| --- | --- | --- |
| 1. Shared semantics | Production verifier/VM/LLVM share CFG and resource rules. Each latest host passed 14 tests, including 30 actual native C ABI/allocator scenarios. | Complete mechanized semantics, whole-language soundness, backend refinement, native quota equivalence and general Rust-class guarantees. |
| 2. Optimization | Final guarded proof-to-machine-artifact binding, refusal controls and nine-dependency scalar receipt provenance. x86 passed 13 binding tests including 2 native; each host passed 7 identity tests with actual Z3 and no skips. | No new general loop, composite, cross-module or peak-resource-reduction algorithm was added. No global optimality or broad performance advantage. |
| 3. Real C++ migration | Two real INIReader versions, 18/18 member dispositions, three partially migrated decision-bearing bodies, actual Hepta compilation and callback cleanup repair. | Foreign parser/STL/native adapter remain trusted. No full C++ translator or whole-component ownership migration; human migration/review/upgrade cost is unknown. |
| 4. NDU planning | Bounded shared-acquisition search, exact-DP and lightweight controls, original native evaluator, actual artifact verification and execution. Both registered 10-episode runs completed correctly. | Both economic results are negative; neither selected a nonbaseline artifact during heldout episodes. No learned predictor or useful adaptive-choice advantage. |
| 5. Agent development | Focused context, full-snapshot patch admission, fair public tools, one terminal hidden evaluation and retained real-provider attempts. | No complete provider answer or complete usage receipt was obtained. Actual A/B efficiency remains blocked. |
| 6. Host/device interfaces | Native Linux x86-64 and AArch64 pthread/eventfd boundaries; each host passed 21 ordered scenarios and observed 244 completed callbacks. | Physical devices, MMIO, DMA, IRQ, kernel drivers, RV64/QEMU, preemptive cancellation and arbitrary concurrent HIA are unqualified. Device availability is unknown. |

The latest hosts each passed 12 safety-protocol and 179 integration tests.
The INIReader qualification executed 48 commands per host: 15.288790267 seconds
on x86-64 and 16.097856699 seconds on AArch64. These are automated qualification
durations, not human migration or upgrade effort. Per version and host, 10,780
Boolean results and 64 object lifetimes matched the original component; 11
callback controls and 36 state/event pairs passed. The original callback-exception
path retained one measured C allocation, while the repaired path retained zero.
That is an explicit resource-behavior repair, not identical exceptional behavior.

## Negative and blocked outcomes are retained

The latest NDU complete measured standalone cost was **39.279519449 seconds**,
versus **11.322619686** for exact DP, **11.309730020** for the lightweight control
and **11.308013916** for fixed-best. Even with the original native build already
paid, native NDU was **11.461603894 seconds** versus DP's **11.322619686**.
The earlier run was independently negative: native **39.715816139 seconds**
versus DP **11.584965177**. These totals include each arm's full observed common
preparation and declared costs; unknown lifetime costs remain unknown.
`competition_established` and measured net-gain acceptance are false in both runs.

Agent attempt 01 used the earlier source: four CLI launches, no complete answer,
unknown usage, startup-warning protocol refusal. Raw `turn.started` events are
present, so it is incorrect to claim no inference began. Attempt 02 used the
latest source but failed local Git registration admission before any launch.
Attempt 03 used the latest source: all four CLI launches received a provider
usage-limit failure, with no complete answer or usage receipt. No failed attempt
is replaced.

## Next acceptance conditions

Each track in the ledger has explicit missing conditions, a next procedure,
pass requirements and the existing executable gate. Re-running existing tests
does not close missing algorithms or proofs. New performance workloads must be
registered before measurement; costs cannot be removed after a negative result.
New C++ migration claims need real previously unhandled revisions, complete
declaration dispositions, changed ownership boundaries and recorded human work.
A real Agent comparison needs complete original provider responses and usage.
Device claims need execution on a registered real board/device and measured
MMIO/DMA/interrupt error, lifetime and recovery behavior.

No broad full-completion flag is true in this ledger.
