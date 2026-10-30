# Owned state at verified native version boundaries

`hepta.hia_stateful.OwnedAdaptiveRuntime` adds one actual persistent native owner
to the existing verified version dispatcher. Its useful supported state is an
exclusively owned array of 1–65,536 `u64` cells. Version changes preserve the
same allocation and its contents. The implementation never resumes a different
version inside an active native frame.

This is a small trusted owner adapter around the existing scalar HIA ABI. HIA
still exports only scalar functions. The adapter owns allocation, length,
progress and cancellation; a verified transition receives only two `u64` values
and returns one `u64`. This does not expose a foreign-buffer ABI or generalize
to arbitrary HIA heaps, live stack frames, active loans, closures or external
resources. The Python host, this native C adapter, compiler, libc, linker,
loader, OS and hardware remain trusted. No absolute language soundness claim
follows from the tests.

## Native ownership and lease checks

The adapter really allocates a control block and a separate data array with
`calloc`; it releases both with `free`. Fault injection tests the first
allocation refusal and cleanup after refusal of the second allocation. Native
allocation/free/refusal counters include all temporary calibration/audit owners.
A successful version change checks the actual private data address and copied
cell contents before and after switching. Public observations contain an opaque
identity bound to that address and owner identity, never a raw pointer or a
writable memory view.

`borrow(mutable=False)` permits shared read leases. `borrow(mutable=True)`
requires exclusive access. Each handle read/write checks its live lease token,
owner identity, generation, bounds, mode and absence of active native work. An
ended handle cannot regain access. Live aliases prevent execution, switching and
destruction. Native work prevents borrowing, switching and destruction. Mutating
a cell after submitting a queue invalidates that queue through its state
revision. No unchecked alias escapes through the public API.

## Total scalar code and deployment authority

The owned adapter accepts one to sixteen pure scalar functions with one block
each, exact `u64` arguments/result, and only total wrapping integer, Boolean,
comparison/select operations. Internal calls form a finite acyclic graph with
a bounded expanded instruction count. Multiple-function programs name their
entry `transition`; it takes `(state, delta)` and returns the next state.
Resource operations, checked arithmetic that might trap, memory accesses,
external effects and recursive calls reject. The original empty-state runtime
retains its original narrower profile.

Every candidate is internally reverified against the current program and built
through `build_optimized_native`. An external receipt, performance dictionary,
shared-library path or function pointer cannot authorize it. The exact bytes
loaded are hashed and held in a sealed descriptor. Publication-path mutation
does not redirect already loaded code. Switching rechecks equivalence,
implementation identity, the complete scalar interface schema and the actual
sealed artifact. The owned state schema and allocation remain fixed.

## Committed finite queues

A queue contains explicit `{slot, delta, iterations}` items. Submission copies
and validates the whole list and binds its digest to the owner identity,
revision and initial values. A runtime retains at most 32 queues, each with at
most 128 items and one billion total transitions, and accepts only one pending
or running queue. A caller cannot change its contents or choose a producer-
estimated future horizon after commitment.

The trusted native loop invokes the selected pure function once per transition,
writes the resulting state cell and publishes atomic progress. Cancellation is
checked between transitions. A completed, cancelled, stale or failed queue is
terminal. `queue_status` returns a detached observation; modifying it has no
authority. A partial native cancellation records the exact committed prefix and
will not execute that queue again. The tests use a real background native loop,
observe positive progress, attempt forbidden switch/close/borrow operations,
then cancel and compare the resulting owner with an independent prefix oracle.

These guarantees concern this live runtime process and its private array.
There are no external effects in the admitted transition. Process-crash recovery,
durable transaction commits and exactly-once external delivery are not
implemented. The API does not claim to solve those different problems.

## Attainable empirical adaptation, with costs

`execute_committed(token, candidate=prepared_token)` calibrates the two actual
native versions on separate cloned owners. It never replays application work
for calibration. Rounds alternate execution order, compare the actual final
states, and free the clones. The forecast uses the smallest observed paired
saving, scaled to the **internally retained committed queue length**. The
measurement is tied to the candidate artifact, owner/revision/generation,
queue digest and a bounded lifetime. Producer estimates are not accepted.

The policy selects a candidate only when that empirical projected saving
exceeds measured preparation and calibration costs; it repeats the cost check
after actual proof and switching. A refusal, expired estimate or exhausted
margin retains/restores the original version before application work begins.
The accounting records the initial baseline/driver construction interval,
every successful or failed candidate preparation interval, prior explicit
switches, queue commitment, calibration, repeated verification, switching,
application execution and commit bookkeeping. Restoration after an observed
loss is also charged. These are specifically delimited measurements, described
below; they are not an end-to-end wall clock for the entire caller session.
This is an empirical forecast, not a guaranteed speedup
or a proof of global optimality. Actual execution may still lose; the receipt
retains that observation, and a loss against the baseline forecast restores the
original version for future work without replaying completed application work.

`audit_counterfactual` is a post-decision qualification tool. It builds a
separate owner containing the saved initial values and runs the original native
version on the exact completed queue. It checks the same final values and
reports `baseline_native_execution_ns - deployment_cost_ns`. This expensive
counterfactual baseline run is **additional experiment overhead** and is listed
as `audit_experiment_cost_ns` and in `total_experiment_cost_ns`; it is neither
free nor decision authority. A positive deployment net does not mean the entire
benchmark experiment was cheaper than simply running the baseline once.

### Internal receipt timing boundaries

The receipt field `deployment_cost_ns` is the sum **P + Q + E + F + R**:

- **P:** measured construction, candidate preparation, prior public selection
  and successful queue submission intervals accumulated by the adapter.
- **Q:** entry to `execute_committed` through completion of queue planning,
  including calibration, proof and selection or pre-execution restoration.
- **E:** the interval immediately around `_apply_items`, including the actual
  native transition calls and the Python loop that dispatches queue items.
- **F:** final progress/revision accounting, copied state and native ledger,
  receipt creation and the queue-finished event, up to its timestamp. This cost
  is charged before deciding whether an observed forecast loss requires rollback.
- **R:** the measured rollback call if that final loss check restores an older
  admitted image.

There are unmeasured tails and gaps: marking a queue running, resetting native
progress/cancellation, the active-call increment, start event and lock release
between Q and E; the final receipt bookkeeping/deep-copy and API return tail;
and the small return tails of earlier preparation methods. Caller-side Core or
proposal generation, caller idle time and final runtime destruction are also
outside these intervals. The audit run has its own measured allocation,
initialization, execution, comparison and release interval. The reported
`total_experiment_cost_ns` sums this **performance comparison's** measured
deployment and audit intervals; it is not the entire qualification script,
which separately runs correctness controls.

Consequently an internal positive result alone is only a gain over those
explicit intervals. It cannot substitute for measuring the complete local API
execution. The forecast remains an empirical policy with loss reporting, not a
guaranteed profitability theorem.

### Complete local API qualification

`tools.qualify_hia_stateful.measure_fresh_deployment` adds an outer monotonic
clock. It starts before reconstructing this fixture's base and candidate
proposal, then creates a fresh runtime, prepares the candidate, constructs and
submits the work queue and waits for `execute_committed` to return. The owner
remains live while a separate timer encloses the entire counterfactual audit
API. The outer clock stops only after `runtime.close()` returns. Only that
complete audit interval is subtracted. Dispatch gaps, all preparation and
execution API tails, receipt serialization and final destruction are therefore
included in `outer_wall.deployment_wall_ns`; the un-subtracted whole experiment
is retained as `outer_wall.total_experiment_wall_ns`.

This is a fresh runtime in an existing Python process. Its deterministic fixture
proposal generation is measured; Python startup/imports and external LLM/NDU
search that the fixture never executes are not part of this stated experiment.
Internal receipt intervals remain available for explaining costs, but the final
profitability gate uses the outer wall-clock result.

The final registered 400-million-transition attempt05 passed correctness and
resource controls but **failed** this complete local profitability gate. The
fixed queue and timer protocol were repeated only because production loading
now binds actual executable symbol mappings to the open sealed artifact's
device/inode. Initial forecast savings covered preparation plus calibration,
but subsequent actual verification/switch costs exhausted that margin; the
baseline was restored before application work. Deployment wall time was
4.019186453 seconds against 3.307593459 seconds of original native execution:
net **−0.711592994 seconds**. The entire performance experiment, including the
independently timed audit, took 7.328442875 seconds. Attempt04's complete local
net of −0.805389844 seconds and earlier internal-interval positive results remain
historical evidence with explicit supersession reasons; none replaces this
final result or establishes global profitability.

## Execution and evidence

```sh
python3 tools/qualify_hia_stateful.py --workdir /tmp/new-owned-runtime-run \
  --clang /path/to/clang-20
```

This executes actual native owner/switch/lease/allocator/cancellation controls
and a short queue whose measured preparation cost prevents automatic selection.
For a separately scheduled performance experiment, append
`--performance-steps N`. That mode constructs a fresh runtime, records the
startup and candidate preparation intervals, runs one actual committed queue, and records
the full counterfactual audit. Success of correctness controls is independent
of whether that queue selected a candidate or achieved a positive measured net;
negative or unselected runs remain evidence and are not renamed successes.

The concrete comparison replaces a modular-add MBA implementation in a pure
helper with wrapping addition, preserving the entry's four-call skeleton. The
checker proves the helper independently over all inputs; native code is then
compiled and actually executed. Two identical artifacts would fail this
qualification. This controlled case establishes only the measured local
optimization, not a general performance advantage of Hepta over Rust/C/C++.
