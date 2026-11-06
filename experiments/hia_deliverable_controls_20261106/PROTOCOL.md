# HIA deliverable controls, 2026-11-06

This directory makes the intelligence/product decision and the existing
negative evidence executable. It contains two independent campaign assessors,
a byte-verified historical index and an independent exhaustive compute-cost
oracle. It does not call a model, build a native executable, train, activate a
policy, or replace any historical experiment. Proposed language capabilities
are specified in [HIA_INTELLIGENCE_CONTRACT.md](../../docs/HIA_INTELLIGENCE_CONTRACT.md).

## Reproduce

From the repository root, run:

```sh
python -m unittest tests.test_hia_deliverable_controls -v
python experiments/hia_deliverable_controls_20261106/controls.py --output /tmp/hia-controls-new-run.json
```

Choose a new output filename for each attempt: the runner refuses overwrite.
The committed `RESULT.json` records this change's actual offline audit. Its
wall time is a local audit cost, not a performance benchmark. Source SHA256
identities are included; repeated runs may differ in measured audit time.

To assess external campaign observations after freezing their protocol:

```sh
python experiments/hia_deliverable_controls_20261106/controls.py --protocol /path/to/frozen-protocol.json --results /path/to/complete-results.json --output /tmp/hia-campaign-assessment.json
```

`tests/test_hia_deliverable_controls.py:fixture` constructs a complete synthetic
protocol/result pair with all required fields. It is solely a test fixture.
The command does not execute the campaign or authenticate its measurements.

## Registered comparisons

| Study value | Exact required arms | Registered contrasts |
| --- | --- | --- |
| `agent_factorial` | `hia_full`, `ordinary_full`, `hia_patch`, `ordinary_patch` | HIA minus ordinary language within each editing interface |
| `ndu_increment` | `ndu`, `mle_exact_dp`, `lightweight`, `fixed` | NDU minus every strong control separately |

Full-file and patch results cannot be pooled into an invented language effect.
NDU and HIA results cannot be pooled. Conventional language and model/backend
versions must be chosen before outcomes. The `information_digest` binds the
complete public instructions, tool/test access and cost-model training data;
`candidate_bank_digest` binds the alternatives; `model_identity_digest` binds
the provider/model for authoring or fitted model for NDU. `hardware_digest`
binds the measured execution environment. The hash preimages belong in the
campaign archive; this assessor verifies equality, not their authenticity.

All task IDs, expected output digests and independence units are frozen. A
project's variants/repeated seeds remain in one unit. At least eight independent
units are required for a conditional positive result. The checker counts
registered units but cannot verify independence or population adequacy. Real
maintenance task selection, training exposure and a power/precision target
remain campaign responsibilities.

## Wire format

The schema constants and exact field inventories are in `controls.py` and are
covered by tests. Inputs must be immutable UTF-8 JSON bytes; duplicate object
keys, nonfinite values, booleans in numeric fields and missing/extra fields
are rejected. The result binds SHA256 of the exact frozen protocol bytes.

Every planned task has every arm represented once. Outcomes are `success`,
`failure`, `refused`, `cancelled` or `missing`. Success must match the frozen
oracle output digest. Missing work has zero attempts and unknown costs; it is
still included in the planned denominator. Failed retries are retained in
`attempts`, `failed_attempt_ns` and the enclosing elapsed measurement. A fast
failure never enters the timing sign test as a fast success. Order of result
rows does not define identity.

For each cell and each arm's setup, every cost metric is an object with exactly
`status`, `value`, `evidence`. Status is `measured`, `not_applicable` or
`unknown`. Unknown requires `value: null` and a reason. Not applicable requires
an explicit zero and evidence/explanation. Measurement receipts should point
to retained raw records; the checker never invents them.

| Metric | Meaning |
| --- | --- |
| `elapsed_ns` | Enclosing lifecycle clock for this cell/setup, including its declared review, repairs, failed attempts, recovery and cleanup |
| `input_tokens`, `output_tokens`, `cached_tokens` | Provider-reported counters; overlap semantics documented in the raw receipt, never blindly summed into billing |
| `billed_micro_usd` | Actual or reconciled currency charge, not token count multiplied by an unregistered price |
| `human_review_ns` | Nested review phase, or explicit evidence of no review in the declared workflow |
| `repair_ns` | Nested repair work, including any retries |
| `failed_attempt_ns` | Nested unsuccessful work, including a failed build/inference |
| `peak_rss_bytes` | Measured peak memory for the stated process envelope |

The declared clock policy is `disjoint_cells_with_enclosing_phase_clocks`.
Setup and cells for an arm must have disjoint enclosing time intervals. Raw
receipts must make the envelope and clock source reviewable. Nested review,
repair and failure clocks are not added to elapsed time. The assessor checks
phase bounds and avoids double counting; it does not authenticate timestamps.
Setup policy is `full_charge_each_standalone_arm`. Complete model fitting,
build, verification, warmup and teardown/setup expenses are charged once per
standalone arm, including failed prior attempts. Arbitrary future amortization
is refused. New metrics or different shared deployment accounting require a
new registered schema, not an implicit reinterpretation.

Complete known cost fields, all correct planned cells, lower total elapsed
including setup, and no billed-cost regression are required. The protocol
registers positive `minimum_gain_ns` and `minimum_gain_ppm` effect thresholds,
plus `maximum_peak_rss_bytes` and `maximum_cell_elapsed_ns`. Failing a registered
effect threshold, memory cap or per-cell deadline blocks a positive result. Per-unit timing
uses sums within each independent unit. An exact one-sided sign probability
uses wins/losses only, retaining ties and unknowns separately. Bonferroni
threshold is 0.05 divided by the number of registered strong-control contrasts.
Unknown or failed units block acceptance. A setup expense can reject a result
even if every per-task time is lower. This is a conditional arithmetic check;
`observer_authenticated`, `task_independence_verified`,
`population_advantage_established` and `production_activation_allowed` remain
false, and authority remains `DENY_ALL`.

For NDU, at least one actual native invocation is required. A cheaper cohort
that skipped every native call cannot establish invocation value. Invocation
counts still need raw call evidence; a supplied count is not self-authenticating.

## Historical index and limits

`HISTORY.json` binds exact upstream commit, source path, URL, byte count,
SHA256 and Git blob SHA1 for each local source copy. All seven sources are
available offline. Large raw artifacts remain referenced by their original
hashes/paths; copying a summary does not mean that raw evidence was rerun,
fully re-archived or accepted against the current candidate. Source revisions
and cohorts remain separate. Hash checking provides immutability, not a
signature from an independent observer.

The generated summary preserves:

- Agent main 14/16 from 2026-10-30, including two HIA repair-exhausted failures,
  three attempts each, all main cell outcomes and incomplete bootstrap costs.
- Round6 Agent 24/24, four arms on six underlying tasks, with unknown token and
  review costs. Equal success counts are not 24 independent wins.
- Both Round6 NDU 72/72 identical native rankings, positive aggregate
  evaluation overhead, all policy generations, all comparator regrets and
  missing human review/maintenance costs. Negative individual timing samples
  also remain in the original summary.
- Separate 54-profile/10,224-state policy closure, same-objective and ordinary
  MPC controls, all reported comparison counts and native/control costs.
- Raw-model and Linux followthrough reports with their unfavorable timings,
  failed build costs and unavailable historic streams. They are indexed as
  source text, never rewritten as a new machine measurement.

The policy report explicitly preserves the compute-price cohort's 72/72
skipped native invocations and unknown/full-cost limitations. That historical
model did not consume future computation time in all deadline-state
transitions; the offline audit here is scoped to the existing stateful
preparation models and cannot be presented as a repair/rerun of that campaign.

## Independent compute audit

`compute_oracle.py` enumerates legal prepared-set schedules directly. It does
not call the production graph compiler, NDU/pruning backend or the existing
reference schedule scorer. It independently computes acquisition, eviction,
holding, delivery, future decision cost, stop placement, integer budget
consumption and Q32 phase rounding. It compares complete winning schedule sets
with the ordinary exact DP for 18 declared v1/v2/v3 fixtures, checks 51 budget
boundaries and 72 invocation-gate cases, and detects cases where omitting future
compute changes value. It retains rejected candidates and abort/abstention
outcomes according to the model. All costs in these fixtures are declared
model inputs. The audit checks source-model agreement; it does not benchmark
native NDU or prove task speedups, full economics, real-time enforcement or
semantic correctness beyond this bounded finite corpus.
