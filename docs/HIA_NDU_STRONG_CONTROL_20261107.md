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

The retained READY-only provider probe and the private synthetic maintenance
task do not qualify a real-user task cohort. The local work initiated no remote
model request and made no production change. `economic_benefit_established`
remains false and P1 remains HOLD. The useful deliverable is a stronger,
budget-honest control and more explicit no-change accounting, with reproducible
negative and positive mechanism observations preserved.
