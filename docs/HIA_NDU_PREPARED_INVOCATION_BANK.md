# Prepared sufficient invocation bounds

The previous source-specific owned-buffer campaign executed zero policy NDU
calls. Its adaptive paths still rebuilt and normalized a full cost model at
each decision. Their twelve controller steps cost approximately 12.7–13.1 ms,
compared with 0.94 ms for fixed selection's request handling. These are retained
observations on `662f05d`, not measurements of this increment.

## One existing bound, prepared once

`hia_invocation_bank.prepare_invocation_bank` uses the existing bounded
`hia_ndu_stateful.validate_model` intake. It accepts at most sixteen
size-indexed templates, each with at most four forecast batches and the same
source, verification, support, status and memory-quota facts. Per-size execution
and holding estimates may differ. The complete captured input is bounded by
500,000 wire bytes. No native result, proof receipt or executable is imported.

For each legal resident mask and prefix horizon, it derives the same two
quantities as the existing `invocation_gate`:

- Incumbent delivery includes the cheapest incumbent/baseline execution and
  every incumbent's holding cost.
- Optimistic delivery grants individually feasible verified variants free
  preparation and future decisions. Monotone v1/v2 retain incumbent holding;
  reversible v3 also grants free eviction and zero holding.

If these quantities are S and L, current invocation estimate I and remaining
budget B, optional planning is considered only when `I + L <= B` and
`S - L > I`. This is the original deterministic-model sufficient bound.
The owner precomputes S/L prefix sums; it does not replace the planner or infer
physical runtime bounds from training estimates.

Every lookup uses new exact integer budget, invocation estimate, bank epoch,
request generation, sunk cost and future-decision cost. It checks the original
complete cost-envelope limit, including future decision charges. Unknown
sizes, invalid resident masks, changed epochs, unsupported horizons and closed
owners refuse. Changing bank facts requires a new owner and paid validation.
Generation and remaining budget are not removed from a cached native-request
key: `NduDecisionCache` is unchanged. Immutable ready identities map to the
bank's fixed mask order.

The private in-memory owner grants only an advisory skip/consider result.
Existing artifact, resource, current-generation and publication checks remain
responsible for execution. The source/verification hashes in these cost models
are still external assertions, as in the original model. This is not a
machine-code safety certificate or arbitrary process-code attestation.

## Correctness checks

`test_hia_invocation_bank` compares every registered size, legal resident mask
and prefix horizon across v1/v2/v3 with the original gate. Current budget and
invocation estimates cover both sides of affordability and savings boundaries.
Seventy-two independent generated cases additionally check that a skip cannot
discard a budget-feasible exact-DP plan whose cost plus invocation is below the
incumbent's delivery cost. These are finite regression observations, not a
mechanized universal implementation theorem.

Other controls exercise intake detachment, source-bank mismatch, epoch drift,
closure, field limits, unavailable residents and the absence of JSON intake,
model hashing, DP or a native call on the hot lookup path.

## Separate prospective mechanism protocol

`benchmarks/hia_native_ndu/PREPARED_GATE_PROTOCOL.json` registers a new
`prepared-bank-v1` profile with new declared episode ordering/seeds. It is a
synthetic mechanism cohort over the existing native kernel, not an unseen
natural application. The historical v3 protocol and its negative observations
remain unchanged. The default command continues to select that v3 protocol.

The prepared bank is built from training sizes before calibration or episodes.
The same sufficient bound is available to DP, greedy and NDU. Every arm starts
from the strongest training-only `fixed_ready` configuration and actually pays
its selection and loading cost. Fixed retains that configuration; adaptive
arms consider only optional changes afterward. This initialization is a strong
fixed fallback, not NDU contribution. Fresh `observed_model` construction
remains inside every adaptive controller measurement. Fixed does not need a
forecast to select its already committed policy, so its comparison model is
constructed only inside the independent-audit measurement. No adaptive model
or gate work moves into that audit bucket. The actual-total comparisons retain
both arms' complete audit work; this is a shared native harness, not a claim
about the lowest possible fixed implementation outside that harness.

The ledger measures complete preparation/validation/derivation, retained input
bytes, prefix count, lookup/rejection counts, close and process peak RSS. The
wire-size/prefix counts do not include Python object overhead, and the process
RSS high-water mark is not an isolated owner allocation measurement. Errors,
actual models, gates, search, native session, transport, loading and cleanup
retain their costs.

In addition to the original service-only comparisons, the report compares
`actual_total_ns`, including every independently recorded audit. Standalone-arm
known-component totals charge the measured common bank work once, each arm's
attributable controller calibration once, and one whole prepared-owner lifetime
to each adaptive arm. Fixed pays no adaptive-owner or NDU calibration cost.
The physical combined campaign's shared cost remains separately recorded;
these standalone totals are not added together as actual campaign wall time.

Calibration harness residue, original NDU build/amortization, tool/source
acquisition, human work, energy and publication remain explicit unassigned or
unknown categories. A faster lookup or a positive known-component comparison
does not establish full-lifecycle NDU benefit. Zero policy NDU invocations
continue to imply that incremental NDU benefit is unestablished.

After committing the implementation and protocol, use one clean frozen source:

```sh
python -B -m unittest tests.test_hia_invocation_bank tests.test_hia_prepared_gate_profile -v
python tools/qualify_hia_native_ndu.py \
  --controller-profile prepared-bank-v1 \
  --build-profile verified-reduction-narrowed-release-v1 \
  --clang /qualified/clang --rustc /qualified/rustc \
  --bridge /qualified/original-stream-bridge --identity /qualified/identity.json \
  --expected-source EXACT_CLEAN_COMMIT --output /new/evidence/directory
```

Do not replace the historical campaign with this result or retry after seeing
an unfavorable native outcome. Natural-workload value and complete economics
remain separate open requirements.
