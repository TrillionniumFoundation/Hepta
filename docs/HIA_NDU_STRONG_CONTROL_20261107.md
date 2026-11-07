# NDU strong ordinary control: implementation and evidence (2026-11-07)

## Delivered change

The ordinary deterministic arm now evaluates **all** disclosed finite
continuation plans against the original remaining lifecycle budget. It no
longer relies on the first supplied candidate. The ranking objective is the
complete forecast remaining wall cost plus its explicit uncertainty allowance.
A continuation must fit both remaining wall time and model-token allowances.
Sunk failed, rejected, timed-out and cancelled attempts remain charged.

The baseline retains the incumbent on equal costs and uses stable plan IDs for
other ties. An empty candidate set is valid. `keep_existing`, `no_adopt` and
`stop` are explicit valid outcomes; contradictory adopt-and-retain plans are
rejected. The ordinary entry returns advisory data with `DENY_ALL`, an original
state digest, decision timestamp offset, its own measured interval and the next
ledger state. It grants no execution or adoption authority.

The local campaign uses this baseline and retains its original advice inside
the measured controller event. Bundle verification recomputes the decision on
that exact frozen state and requires the internal controller interval to fit
inside the outer charged event. The event is charged once. Provider-enabled
ordinary campaigns still follow their actual same-model ordinary advice.

### Interfaces and integration

- `hepta.hia_agent_macro_policy.ordinary_plan_selection`: deterministic replay
  over the exact supplied finite state.
- `hepta.hia_agent_macro_policy.advise_ordinary`: wire validation, measured
  controller attempt and persistent next ledger.
- `python tools/hia_agent_macro_policy.py ordinary --input STATE --output ADVICE`:
  caller-side CLI.
- `tools/qualify_hia_macro_campaign.py`: same-budget ordinary campaign arm and
  verification of retained ordinary advice.

The installation/discovery contract exposes the ordinary entry and legal
no-change outcomes. This changes worker source identities. The patch was
prepared from Core `894d2dfce54ff25271b8de2c18c902394484d5cc`; existing exact-v4
production attestations do not attest this changed candidate. Integration must
pin its new worker identity and repeat the applicable release checks.

## Verification

The focused suite contains 73 passing tests:

```sh
python -m unittest tests.test_hia_agent_macro_policy \
  tests.test_hia_macro_strong_control tests.test_hia_macro_campaign \
  tests.test_hia_macro_codex_provider -v
```

Ten new tests cover all-plan enumeration, source-order independence, incumbent
ties, wall/token infeasibility after sunk failures, uncertainty, empty candidate
sets, valid keep/stop/refusal outcomes, contradictory plans, incomplete costs,
cancellation retention, repeated controller cost, campaign integration and
bounded schema rejection. The suite also retains the existing adversarial
original-receipt, provider-usage, budget and economic-acceptance checks.
The retained [test log](../review-evidence/hia-ndu-strong-control-20261107/unit-tests.log)
contains the actual result.

A fresh local campaign is recorded separately in
[the local campaign summary](../review-evidence/hia-ndu-strong-control-20261107/local-campaign-summary.json). Its initial attempt ran in an environment missing
`jsonschema`: all 32 planned arms failed during discovery and all 32 failures
and elapsed costs were retained. The subsequent run used an existing Python
virtual environment and completed all 32 native task arms correctly. Its 440
events and 1,457 original objects verified; all eight ordinary advice records
passed exact-state decision replay. The [original archive](../review-evidence/hia-ndu-strong-control-20261107/local-native-originals.tar.gz)
preserves both complete runs, including failed discovery and driver output.
These runs exercise campaign mechanics, not a real Agent or NDU value comparison. No provider was invoked and no native NDU
bridge was supplied to these local runs.

## What the original native records establish

The original two native campaigns each contain eight deterministic wrapping-u8
tasks and four policy arms. The original bytes and their causal/cost bindings
were rechecked with `verify_campaign`. Each campaign retained 32 correct native
task arms and eight original native NDU evaluations. See the
[retained decision replay](../review-evidence/hia-ndu-strong-control-20261107/retained-native-replay.json)
for original manifest, state and result digests.

| Original campaign | Best ordinary control wall ns | NDU wall ns | NDU saving ns |
| --- | ---: | ---: | ---: |
| r1 | 6,965,414,782 | 7,077,247,310 | -111,832,528 |
| r2 | 7,065,319,196 | 6,973,433,766 | 91,885,430 |

These are the original measured task-arm totals, not new measurements from this
patch. The sign of the saving changes between runs. Replaying the new ordinary
rule on the 16 retained original NDU pre-decision states matches all 16 native
choices. Every state contained only one candidate. This establishes consistency
for that narrow supplied-cost decision domain; it does not establish a new
lifecycle performance comparison, a policy advantage or general optimality.

The recorded post-decision use is actual full-domain native execution of the
selected artifact. Stopping optimization can therefore still deliver the
original task through the incumbent. A forecast of future use is never booked
as realized benefit. Historical native results must remain distinct from this
patch's unit tests and offline replays.

## Acceptance remains HOLD

The finite scalar-cost baseline is exact over its disclosed candidate set and
budget constraints. It is not a best-known general learned Agent policy, and
uncalibrated supplied forecasts are not ground truth. A real evaluation still
needs the following evidence:

1. Preregistered representative real user tasks, independent correctness and
   quality judgments, and the same model, tool context and total allowances for
   every arm.
2. A strong same-model ordinary policy, budget-adaptive or search baselines,
   repeated runs and explicit uncertainty. Each baseline must have equal access
   to candidate and cost information; unpublished future observations cannot
   feed the policy.
3. Original provider usage and monetary receipts, plus setup, discovery,
   failures, retries, search, verification, emission, evaluation, adoption,
   downstream use, rollback, controller and any human cost. Unknown values
   remain unknown; token totals are not dollar costs.
4. Actual final artifact use and delivered task value, with adoption optional.
   KeepExisting, Stop and NoAdopt must be eligible winners. Cancelled or
   timed-out work cannot disappear from either arm's budget.
5. Independently authenticated original task/provider/native receipts. Local
   hashes prove byte consistency, not independent provenance.

The earlier READY-only provider probe and the private synthetic maintenance
task do not qualify a real-user task cohort. The local baseline work above
initiated no remote model request and made no production change. A later
provider campaign did execute; its retained terminal result is reconciled
below. `economic_benefit_established` remains false and P1 remains HOLD.


## Later exact-v4 provider execution: original terminal result reconciled

The original `ndu-provider-v4-campaign-r1` actually ran on 2026-11-07, using
Core `894d2dfce54ff25271b8de2c18c902394484d5cc` and its pinned launch adapter.
It is a separate, later event from the READY probe. The original supervisor
record says campaign exit 2 and verification exit 0, with zero automatic
retries. All 32 provider processes have retained terminal five-field usage and
confirmed cleanup. Of those, 27 produced completed provider proposals and
22 delivered correct native task results. Seven original native NDU evaluations
are recorded. These historical results are not measurements of the newer
integrated source or of the reporting change below.

| Arm | Planned tasks | Completed provider proposals | Correct native tasks | All-attempt wall ns |
| --- | ---: | ---: | ---: | ---: |
| Fixed | 8 | 7 | 2 | 130,466,301,676 |
| Greedy | 8 | 7 | 7 | 134,985,846,220 |
| Ordinary | 8 | 6 | 6 | 151,383,646,332 |
| NDU | 8 | 7 | 7 | 113,450,243,024 |

Sources: [retained facts excerpt](../review-evidence/hia-ndu-completed-control-20261107/retained-provider-facts.json),
[original cost and scope receipt](../review-evidence/hia-ndu-completed-control-20261107/original-cost-and-scope.json),
and [original supervisor result](../review-evidence/hia-ndu-completed-control-20261107/original-execution-result.json).
The facts excerpt carries the SHA-256 of its original full receipt. The cost,
supervisor and comparison files are byte-for-byte copies. Original campaign
identity, manifest, comparison and verdict digests are retained in
[the reassessment receipt](../review-evidence/hia-ndu-completed-control-20261107/retained-provider-reassessment.json).

The original verifier retained 420 events, 1,441 original objects and 42 failed
or rejected attempts. Ten task arms failed: five at final model JSON parsing
and five at candidate Core admission. Those failures and their costs remain in
the original 32-task-arm denominator. Every arm delivered fewer than eight
correct results, so there is no completed control and no complete NDU arm.

The supervisor measured 531,558,629,396 ns for the campaign and 287,456,723 ns
for original-byte verification. The model phase contains 493,868,197,094 ns;
its provider subprocesses contain 493,583,641,701 ns. These are nested cost
boundaries and are never added to the outer total again. The original five
usage counters total 306,442 input tokens, 16,149 output tokens, 112,896 cached
input tokens, zero cache-write input tokens and 4,715 reasoning output tokens.
The historical budget convention charged input + output + reasoning = 327,306;
input + output alone is 322,591. Cached input is not charged twice. Whether the
reasoning counter overlaps output is not independently attested. Money, tariff
and invoice remain unknown. Setup, diagnostic and the earlier native build
boundaries are retained separately in the original cost receipt.

The campaign used source-authored synthetic wrapping-u8 tasks and local
in-process HIA. Its ordinary arm made one bounded same-model proposal/advice
call per task; this does not establish a strongest general Agent baseline.
Original provider streams contain only `agent_message` items, but a complete
capability-isolation attestation is absent. Hash consistency is established;
independent provider/native provenance is not. The original terminal verdict
therefore remains HOLD, native mechanism incomplete, and economic benefit
unestablished. No failed arm was replayed for this reconciliation.

## Reporting fix: complete task delivery before a headline cost difference

The old result's `best_control = fixed` and `ndu_saving_ns = 17,016,058,652`
were raw wall arithmetic. Fixed delivered only 2/8 correct tasks. That number
cannot support a gain over a completed ordinary control, and cannot be made
qualified by selecting only the successful tasks or silently dropping another
registered arm.

`assess_macro_comparison` now returns `completed_comparison` with each arm's
eligibility and the exact reasons for ineligibility. A headline
`completed_comparison.ndu_saving_ns` is available only when **every** registered
arm delivers every task correctly, keeps its result evidence and complete
charged costs, observes Agent and downstream use, fits the original wall/token
budget, and retains the NDU arm's required native evaluations. A failed strong
ordinary arm cannot be silently replaced by a weaker completed control.
`best_complete_control` is diagnostic only when the full comparison is not
eligible; it grants no qualified saving.

The historical v1 fields remain intact for compatibility. They are explicitly
labelled by `legacy_cost_fields_scope`, and the same raw values are also
available as `raw_lowest_cost_control` and `raw_ndu_wall_difference_ns`.
The campaign CLI's headline `ndu_saving_ns` now uses the qualified complete
comparison and prints raw diagnostics separately. This change preserves all
attempts, existing budgets, raw totals and acceptance reasons. A complete
supplied observation is still subject to task/provenance qualification and is
not by itself an economic attestation.

The retained original comparison reassesses to `complete_controls = []`,
`best_complete_control = null` and `completed_comparison.ndu_saving_ns = null`.
All four original wall totals and the raw 17,016,058,652 ns difference are
unchanged. This was a read-only computation over retained original comparison
bytes, with zero new provider calls and no new native execution.

Reproduce the assessment from this checkout with Python; the output path must
not already exist:

```sh
python -B tools/hia_agent_macro_policy.py assess \
  --input review-evidence/hia-ndu-completed-control-20261107/original-comparison.json \
  --output /tmp/hia-ndu-original-provider-assessment.json
```

Exit 2 is expected because this original evidence remains HOLD. This command
only reads the retained comparison and writes a new assessment file. It does
not launch the original campaign or a model request.

The focused suite now passes **77 tests**. Four additional regression tests
cover incomplete controls with all costs retained, refusal to skip an
incomplete ordinary arm, unknown costs or missing evidence or downstream use
or exceeded token budgets, and a complete synthetic comparison whose supplied
arithmetic is available while economic acceptance remains HOLD. The
[current test log](../review-evidence/hia-ndu-completed-control-20261107/unit-tests.log)
retains the actual 77-test result. Integration must freeze the changed source
identity; neither the historical exact-v4 receipts nor an earlier integrated
release lock attests these new bytes.
