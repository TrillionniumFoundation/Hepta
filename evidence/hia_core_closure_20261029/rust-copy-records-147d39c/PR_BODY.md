## Why

Rust execution previously received primitive Core only after Python had performed every composite nominal check. That left Python normalization on the admission path even when the existing Rust Machine executed the result. This change implements one explicit native nominal input candidate and does not switch production authority.

## Changes

- Add native `--composite-record-normalize` and `--composite-record-run-bound-v1` commands for raw `hepta.hia.composite.v1` monomorphic Copy records. Scalar, nested and empty record fields are admitted; primitive byte resources remain usable inside functions but cannot be stored in these records.
- Preserve original nominal types, SSA names and arity before erasure at constructors, accesses, calls, returns and CFG edges. Distinct same-layout records and zero-width records cannot become interchangeable. Export eligibility comes from original scalar-only signatures, so an empty record helper remains private.
- Normalize to the existing primitive v6 Core, reverify the whole generated module with the existing checker, and execute through the existing bound-v4 Machine. The outer request binds both canonical original nominal input and actual Core identities, ordered arguments and the complete policy. There is no new evaluator, Core schema, imported admission receipt or Python fallback.
- Fail the whole module on unsupported or malformed declarations/functions, including unused ones. Generic, enum, task, partial-record, resource-field and later-composite forms remain outside this explicitly documented candidate.
- Charge checked scalar-reference expansion widths before cloning or collecting names. Review found and corrected both repeated wide-binding fan-out before charging and entry-function parameter duplication before charging. The original draft snapshots and finding records are retained outside the source tree.
- Register the candidate branch additively in the existing full-gate and both host-matrix push allowlists. Existing exact-head checkout, failure/skip gates, budgets, permissions and triggers are retained.

## Qualification

The following required commands actually passed on clean public commit `147d39c4a9d3ded00fb5d22439493bc006a8b76d`, tree `2050ec5e447ae5191ac2e685ba463292b2d2d3fe`, parent `99cf106586509b08bb2b9890ed29cf042336d69e`. The same required gates also passed separately on original local commit `505dd0435d48b687f97daba5dc9771c1473ba8a1`:

| Gate | Actual denominator and outcome |
| --- | --- |
| Entire Rust crate | 96 tests in 19 result harnesses; no failure, ignored test or filter |
| New raw-record collector | 9 methods; 13 exact Core/export comparisons, 43 execution observations, 47 raw refusals; 103 actual native processes |
| Existing bound-v4 collector | 8 methods; 155 observations, 37 raw refusals, 72 retained legacy comparisons |
| Existing composite-v4 collector | 13 methods; 153 Rust observations, 4 raw Rust refusals, 31 actual native calls |
| Related source/protocol/workflow guards | 20 methods |

All test methods completed with zero failures, errors, skips, expected failures and unexpected successes. The collectors bind actual source, tools and executable before/after identities. The new native child receives original raw input from a temporary directory with no Python on PATH; Python admission, elaboration and Machine functions are disabled during launch. A Python oracle is evaluated separately afterward. This establishes the observed native path, not a hostile-host sandbox.

The safety matrix retains all original 116 selectors and adds 10, for 126 selectors across 17 capabilities. The integrated inventory now lists 49 groups and 122 unique modules. These are discovered registration counts, not a claim that all 126 selectors or a new full integrated gate ran locally.

The 15-file UTF-8 export and full-index patch reproduce the exact frozen tree when applied to an isolated index at the public parent. Local executions retain their local commit identity. Fresh public-source execution rebuilt identical Rust executable bytes with source and tools unchanged. Independent review performed 13 additional native invocations on the original local commit: one exact normalization, three full v6 execution matches, two private empty-signature refusals, four nominal/SSA/CFG refusals and three fan-out refusals under a 128 MiB address-space cap. The latter codes were respectively `E_HIA_LIMIT` for return expansion, `E_HIA_CALL` for a malformed call and `E_HIA_TYPE` for a malformed edge. A reviewer-only `live_chains` assumption for the v6 ledger failed during aggregation; its original script/logs were retained and completion used the same 13 original native outputs without replays. Both draft source findings are closed. Hosted CI results remain a separate exact-head gate.

## Remaining boundary

Production admission and execution routes remain Python; optimization policy remains `no_change`. General composite normalization, the complete Python API domain, deployment eligibility, cleanup/cancellation, backend refinement and broad P2 closure remain open. Queued workflows, a mergeable draft PR or finite agreement do not close those obligations.
