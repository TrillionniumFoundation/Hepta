# Macro continuation observations, 2026-11-07

Two complete preregistered runs of the original-receipt macro mechanism fixture
executed 32 native task arms each, including eight source-bound original native
NDU evaluations. Both retained all 32 deliberately rejected search attempts,
verified every expected native result, and remained P1 HOLD. Tasks and controls
in these two observations were deterministic fixtures: no provider call or
billing cost is inferred from them.

| Observation | Fixed total wall ns | Greedy total wall ns | Ordinary total wall ns | NDU total wall ns | NDU saving against best control ns |
|---|---:|---:|---:|---:|---:|
| r1 | 24,770,923,293 | 6,974,823,810 | 6,965,414,782 | 7,077,247,310 | -111,832,528 |
| r2 | 24,463,303,158 | 9,770,355,432 | 7,065,319,196 | 6,973,433,766 | 91,885,430 |

The sign reverses between runs. These measurements show that the decision can
avoid subsequent actual search work, while the ordinary cost controller can
obtain that benefit too. They do not establish an NDU advantage. In r2, greedy
selected search once when its one-step comparison crossed the observed threshold;
all outcomes and costs were retained. Future use is one actual full-domain batch
per task arm, not hypothetical amortization.

r1 verified 440 event receipts and 1,457 original objects. r2 verified 447 event
receipts and 1,473 original objects. r2 charged 48,272,411,552 ns to task phases,
plus 590,866,459 ns for campaign setup, intermediate exports and cleanup, for
48,863,278,011 ns through the manifest endpoint. Final manifest/verdict export and
imports before the clock are explicitly outside that endpoint. Native nested
measurements are not added again.

The bundles retain the exact source/worker inventories used at execution, so
these observations are not silently rebound to later changes to the provider
adapter. The later optional Codex integration is tested for raw receipt,
configuration and budget consistency but was not used in r1/r2.

Actual local evidence locations for this working session:

- `/workspace/scratch/372e7da9bde9/macro-campaign-20261107-r1`
- `/workspace/scratch/372e7da9bde9/macro-campaign-20261107-r2`

Each directory contains its original registration, campaign manifest, verdict
and content-addressed original bytes. The verifier checks internal byte and
causal/accounting consistency, not independent author authentication. Required
remaining work includes an actual available provider on the coordinator host
(or a separately qualified remote transport), genuinely required tasks with an
independent judge, complete monetary/human-cost evidence, calibrated forecasts,
and repeatable measured advantage over every control within the frozen budget.
