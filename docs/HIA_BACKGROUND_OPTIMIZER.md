# Finite background optimization and conditional publication

`hepta.hia_background_optimizer.BackgroundOptimizer` connects the original native
NDU evaluator to the independent HIA translation validator and the scalar native
generation runtime. It has one worker and at most eight outstanding jobs,
including the active job. It publishes a complete new generation only after
proof, native preparation, a positive modeled net benefit, and an atomic check
that the incumbent snapshot is still current.

This consumer inherits the finite, total, effect-free scalar profile in
[HIA_MULTIVERSION.md](HIA_MULTIVERSION.md). It does not move owned buffers, repair
stack frames, change object layouts, patch executable instructions in place, or
establish whole-program global optimality. The Python verifier remains the
production semantic authority. NDU ranks proposals; it does not grant safety.

## API

```python
from pathlib import Path
from hepta.hia_background_optimizer import BackgroundOptimizer
from hepta.hia_multiversion import ScalarMultiversionRuntime

with ScalarMultiversionRuntime(baseline, artifact_directory, clang="clang") as runtime:
    with BackgroundOptimizer(
        runtime,
        baseline,
        function="calculate",
        bridge={
            "binary": Path("build/hia-ndu-bridge"),
            "build_receipt": Path("build/build-receipt.json"),
        },
        max_pending=8,
    ) as background:
        future = background.submit(candidates, observations, objective)
        result = future.result()
        answer = runtime.call("calculate", [17])
```

`baseline` must bind the immutable original baseline already held by `runtime`,
including both the canonical Core hash and the input hash. The coordinator does
not own or close the shared runtime.

`candidates`, `observations`, and `objective` use the exact schemas of
`hepta.hia_ndu_optimizer.rank_candidates`:

```python
candidates = [
    {"id": "remove_identity", "action": "remove_wrapping_add_zero", "program": candidate},
]
observations = {
    "abstain": {
        "runtime_ns": baseline_cost,
        "uncertainty_ns": baseline_radius,
        "search_ns": measured_baseline_search_cost,
        "program_sha256": current_core_sha256,
    },
    "remove_identity": {
        "runtime_ns": candidate_cost,
        "uncertainty_ns": candidate_radius,
        "search_ns": measured_candidate_search_cost,
        "program_sha256": candidate_core_sha256,
    },
}
objective = {
    "expected_calls": horizon_calls,
    "resource_cap_ns": total_optimization_budget,
    "target": "x86_64-unknown-linux-gnu",
    "measurement_profile": "name_of_the_actual_measurement_protocol",
}
```

All times and counts are exact integers. Supplied timings remain trusted host
observations. A measurement profile is descriptive text, not a performance
attestation or an admission switch. Caller-provided `ok`, `admitted`, proof
receipts, and other extra fields do not authorize publication. The native bridge
and its local build receipt are freshly checked by the ranker on each invocation.

## Snapshot and source custody

Submission performs a structural byte/node/depth preflight before copying the
JSON. The entire frozen submission is bounded by the canonical HIA JSON limits.
It then captures the runtime's current generation and selection epoch. Caller
mutation after `submit` cannot change queued programs, observations, or goals.

The coordinator retains immutable source bytes for the original baseline and
the most recent program it successfully published. Ranking uses the exact
current source; publication independently proves equivalence to the runtime's
original baseline. A current source outside that tracked set rejects submission.
The coordinator never guesses a new incumbent or silently reuses old timings
for a different program.

Each job binds both `expected_generation` and `expected_selection_epoch`. Epoch
comparison catches a publish/rollback sequence even when the selected generation
number returns to zero. NDU requires a nonzero decision generation, so its
`generation` is explicitly `expected_selection_epoch + 1`; this is recorded
separately from the native generation number.

If two queued jobs capture the same incumbent and the first publishes, the
second returns `stale`. It is not automatically rebased. New observations and a
new submission are needed for the new incumbent.

## Admission and actual cost accounting

For a selected candidate, the ranker computes the incumbent's lower estimated
cost and the candidate's upper estimated cost over the explicit call horizon.
It charges every supplied search cost once, together with the invocation's
actual validation, native NDU evaluation, and selected-candidate reproof time.
Its `net_margin_ns` excludes native publication preparation.

The coordinator checks the returned program against the frozen submitted
candidate, verifies the incumbent/function/objective/observation/generation
bindings, and recomputes the reported margin from the submitted observations and
costs. It charges submission work and its actual work outside the time already
charged by the ranker. Ranker return/report construction time is included rather
than counted twice or omitted.

The remaining publication budget is the smaller of:

1. positive remaining modeled savings, leaving at least one nanosecond; and
2. the remaining total optimization resource budget.

`ScalarMultiversionRuntime.publish_if_current` then performs a fresh canonical
verification, ABI check, independent proof of every exported function against
the original baseline, direct LLVM build, exact artifact checks, sealed loading,
and actual native/interpreter probes. It measures preparation through the final
check immediately before the selection change. The coordinator passes an
earlier monotonic handoff timestamp so call setup and writer-lock waiting also
consume the budget. A preparation overrun disposes the unselected artifact and
preserves the incumbent.

This is an admission check over a stated cost model and trusted measurements.
It is not a proof that future execution time stays within the measurement
radius. Queue wait, native return/retirement bookkeeping after the swap, and
Future/receipt completion are recorded separately from the prepublication gate.
The result names the remaining quantity
`net_margin_before_postcommit_reporting_ns`; it does not report a measured
end-to-end speedup. Cold compilation, measurement, or toolchain preparation must
be included once in `search_ns` for whichever horizon is intended to amortize it.

## Cancellation, publication, and shutdown

`future.cancel()` remains available while the worker ranks, proves, or builds.
Cancellation is cooperative: a running native compiler or solver may finish
before the worker disposes the unselected preparation. A successful cancellation
guarantees that the job cannot subsequently change the selected generation.

The runtime's `PublicationCancellation` shares a lock with the final commit
decision. An Event check alone would leave a race between the check and the
pointer swap. The commit marks the token under the runtime selection lock, so
cancellation after commit returns `False`, including the interval before the
Future result has been completed. Arbitrary user callbacks never run under the
runtime lock, token lock, or a coordinator completion lock.

The returned Future stays pending until completion or commit rather than being
marked noncancellable when background preparation starts. Cancelled futures
notify `concurrent.futures.wait` and `as_completed` before invoking user
callbacks. A completion callback may call `shutdown`; the worker never joins
itself, and cancellation callbacks do not hold a lock needed by worker exit.

```python
background.shutdown(wait=True, cancel_pending=True)   # default: request cancellation
background.shutdown(wait=True, cancel_pending=False)  # drain the finite queue
```

Shutdown first rejects new submissions. Cancellation covers queued and active
jobs that have not committed; it does not undo an already committed generation.
With `wait=False`, shutdown returns before the worker exits. Cancellation does
not immediately release a capacity slot: the worker removes the cancelled job
before that slot becomes available. Copying the coordinator or cancellation
token is rejected to preserve one owner of the lifecycle/synchronization state.

## Results and failure behavior

`future.result()` returns a `hepta.hia.background-optimization.v1` document.

| Status | Meaning |
| --- | --- |
| `published` | Fresh proof, native preparation, positive modeled cost gate, and conditional selection all succeeded. |
| `abstained` | NDU abstained or the remaining coordinator/preparation budget could not justify publication. |
| `stale` | The current generation or selection epoch no longer matches the submitted snapshot. |
| `rejected` | Verification, proof, identity, native preparation, or a required report binding failed. |

A cancelled Future raises the standard `CancelledError`. Malformed submission
shape, wrong target, wrong incumbent measurement, unknown current source,
shutdown, and capacity exhaustion may reject synchronously before enqueueing.
Unsupported behavior, unknown/disproved proof results, stale snapshots,
cancellation, and preparation overruns do not select the candidate. The
existing runtime continues to retain active generation leases and dispose old
generations under its normal lifetime rules.

## Executed qualification

```sh
python -m unittest tests.test_hia_background_optimizer tests.test_hia_multiversion -v
python tools/qualify_hia_background_optimizer.py \
  --clang /path/to/clang \
  --bridge /path/to/hia-ndu-bridge \
  --bridge-build-receipt /path/to/build-receipt.json \
  --output /new/path/background-qualification.json
```

The unit tests preserve actual canonical verification, Z3 proofs, compilation,
sealed loading, and native execution. Controlled ranking results and Events
exercise snapshot changes, rollback ABA, queued-job staleness, cancellation
during real native preparation, cancellation after atomic commit, unknown and
disproved proofs, real preparation overrun, frozen input mutation, queue limits,
shutdown/drain, Future wait notification, and callback/worker-join races.

The standalone qualifier additionally executes the original native NDU bridge
for three distinct requests. It performs 14,592 native lease calls to measure a
baseline and a candidate, charges cold builds once to a one-call horizon, and
requires the measured decision to abstain. A separately labelled synthetic
economic control exercises actual publication through NDU, fresh SMT proof,
compilation and loading. A cheaper behavior-changing proposal obtains an actual
counterexample, and a subsequent invalid proposal preserves the selected head.
Synthetic costs are never presented as benchmark results.

The `hepta.hia.background-optimization-qualification.v1` receipt sets `ok: true`
only after those mechanisms, source stability, native outputs, drain, and final
generation cleanup have been observed. It retains source hashes, exact programs,
measurement samples, all three NDU requests/responses and proof reports,
publication costs, native outputs, and lifecycle snapshots. Performance
improvement, independent measurement attestation, backend refinement,
whole-language soundness, resource-state migration, and global optimality remain
explicitly unestablished.
