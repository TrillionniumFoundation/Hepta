# Explicit computation time in the finite resource model

The existing computation-price experiment subtracts forecast planning fees from
its opportunity comparison, but its future states subtract only workload cost.
The native episode already records controller plus workload elapsed time in the
final outcome. Its original dispatch guard only checks whether controller time
alone exceeds available resources, leaving a gap when computation finishes but
the remaining resources cannot fit the selected workload.

The separate [compute-debit profile](../benchmarks/hia_ndu_feedback/COMPUTE_DEBIT_PROTOCOL.json)
addresses those two finite-model defects. It is opt-in and does not relabel the
original frozen cohorts or give their v1 bounds a new interpretation.

## Forecast transitions

`ComputeDebitProfile` binds one scenario, an explicit calibration identity and
an immutable forecast table indexed by **remaining horizon minus one**. Raw
resource costs must explicitly be nanoseconds. `cost_unit` remains the existing
nanoseconds-per-utility-cost conversion. A future formal campaign must freeze
training-only calibration inputs before held-out execution; a supplied hash
does not establish that the calibration was valid or independently measured.

`model.plan(..., compute_profile=profile)` reuses the existing recursive planner,
action costs and observation forecast. At every root and future node it:

1. Obtains the declared computation duration for that remaining horizon.
2. Projects `budget - compute` and `deadline - compute`, saturating at zero.
3. Refuses new work if computation reaches either resource limit or the
   registered workload forecast exceeds the remaining resource projection.
4. Passes `budget - compute - workload` and `deadline - compute - workload` to
   the existing successor transition.
5. Includes compute plus workload in utility once. Abstention still pays its
   computation fee. The current-step price is fixed by the incoming observation,
   matching the existing environment's measured-total-cost transition.

The native backend receives the combined resource cost and an objective digest
that includes the profile identity. The new plan schema and every search-node
receipt distinguish these semantics from the unchanged v1 model. Ordinary
planning and NDU use the same transition code; an explicit scalar backend in
tests is a correctness control, not an original-native execution claim.

A hand-checkable counterexample is covered by the regression suite: with two
requests, a budget of 8, workload cost 3 each and a second-decision computation
forecast of 3, the old model can deliver both requests. The profiled model leaves
only 2 before the second service, correctly makes that service infeasible, and
retains the remaining-request penalty and computation cost.

## Actual dispatch and single charging

`episode(..., compute_profile=profile)` uses the existing actual-workload route.
Before the callback, `dispatch_after_compute` measures elapsed time from the
step's original monotonic start and validates the decision and profile identity.
It projects the real remaining resources and checks the registered workload
forecast again. No workload callback runs when the deadline is already reached
or insufficient forecast resources remain. A stale, unprofiled or rebound plan
is rejected.

The resource projection does **not** mutate the environment. After work or
abstention, the original `env.step` receives the measured whole-step duration
exactly once. For example, a predicted compute cost of 5, observed compute cost
of 3 and observed workload cost of 4 consume **7**, not 10, 12 or 15. The next
observation carries that actual debit. Prediction fees and observation subtotals
are never added again to the already inclusive measured total.

A callback that overruns is still reported as an executed action with an actual
budget failure. A callback that fails after it might have produced effects
retains an `UNKNOWN` effect status and elapsed-cost receipt; it is not retried.
Initialization, cleanup and between-step bookkeeping remain in the separate
episode wall ledger, as in the original runner.

## Explicit limits and validation

The new profile does not provide a worst-case execution-time bound. The gap
between sampling the clock and entering the callback is not an OS reservation;
native work is not preempted and past effects are not undone. Both plans and
dispatch receipts explicitly keep `hard_realtime_guarantee=false`.

The old `priced_plan` lower bound and the old independent oracle use workload-only
future transitions. They refuse the new profile instead of certifying it under
the wrong model. A new compute-aware price bound and an independent full-policy
oracle remain separate work. No training or native performance campaign is
introduced by this patch, and none of these changes executes an NDU controller
inside the Linux kernel.

Run the deterministic counterexamples and neighboring reference regressions:

```sh
python -B -m unittest \
  tests.test_hia_ndu_compute_debit \
  tests.test_hia_ndu_feedback \
  tests.test_hia_ndu_feedback_campaign \
  tests.test_hia_ndu_economical \
  tests.test_hia_ndu_compute_price \
  tests.test_hia_ndu_feedback_ci_paths
```

The tests cover a controller wait exhausting the deadline before dispatch,
remaining-workload infeasibility, future-state debits, once-only utility and
resource charging, actual overruns, failed callback uncertainty, stale identity,
clock regression and the real episode integration with explicitly labeled
controlled transports. They establish implementation correctness within that
scope, not physical performance or NDU-exclusive benefit.
