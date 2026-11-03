# Stateful NDU v2: paid decisions and invocation refusal

This increment changes the bounded advisory model and its native measurement
campaign. It does not establish application speedup, complete lifecycle cost,
an NDU advantage, whole-language safety or production permission. Historical v1
models and their negative empirical results remain valid records of those runs.

## Version and continuation semantics

`hepta.hia.ndu.stateful-preparation.v1` retains its exact field set and zero
future decision cost. Supplying a new cost field with the old schema refuses.
`hepta.hia.ndu.stateful-preparation.v2` requires the additional integer
`future_decision_cost_ns`. Negative, Boolean, fractional, missing, excessive and
unknown values refuse before a native request exists.

The existing finite-graph representation already distinguishes an active
decision from stopping. V2 now passes its explicit cost into that representation.
The current invocation is outside the continuation value. Each active decision
after batch zero pays the supplied cost, including the decision to stop.
Subsequent stopped delivery pays no decision cost. Acquiring a candidate pays
preparation once; every retained candidate continues to occupy its declared
resident bytes and incur its holding cost, even when another candidate executes.
Prepared candidates cannot be forgotten in this profile.

For a prepared-set schedule, its least expensive compatible stop occurs one
batch after the last acquisition, unless that acquisition was the final batch.
A schedule that keeps only its existing prepared set stops at batch zero. The
independent reference enumerator scores this rule directly. Its separate DP
recurrence chooses complete stopped delivery or one active step followed by a
new subproblem. Neither calls the production graph builder or pruning code.
Setup plus decision and execution plus holding retain the wire's separate Q32
rounding. Positive-cost counterexamples change the chosen acquisition time.
The strong fixed control precommits its complete resident set in the current
call and is therefore charged zero future controller calls. It can outperform
the active planner when those future calls are expensive; inflating its cost
by a fictitious later stop decision would invalidate the comparison.

## Why the invoke/skip bound is conservative in the model

Let `S` be the remaining execution and holding cost of retaining the incumbent
prepared set. Let `L` select, independently at each remaining batch, the fastest
baseline or individually memory-feasible verified candidate. `L` charges the
incumbent's unavoidable holding cost but gives all new candidates free
preparation, no additional holding cost and no future decision cost. It also
allows choices that could exceed the joint resident quota when combined.

Every legal monotone prepared-set schedule has cost at least `L`: it can use
only those candidate alternatives, must retain the incumbent, and pays
nonnegative costs that the relaxation removes. Thus `S - L` is an upper bound
on the savings from any legal schedule in the supplied nanosecond model. If
the current invocation estimate `C` satisfies `C >= S - L`, invoking cannot
strictly improve on retaining the incumbent in that model. If `C + L` exceeds
the remaining budget, even the optimistic invoked delivery is unaffordable.
The caller skips in these cases and retains the current prepared set.

The argument is about the declared deterministic cost model. Measured timing
estimates are not bounds on future host time. The gate does not prove an
empirical improvement, a Q32 ranking theorem, an arbitrary stochastic control
optimum or safe machine code. Its own actual work must be charged.

## Measurement and cost accounting

The native economics v2 campaign calibrates each controller using only frozen
training sizes, before any episode is disclosed. It retains one complete actual
call per training size for exact DP, greedy and native NDU. Calibration forces
these calls to measure their cost, even where an operational gate would skip.
It includes model construction, the invocation gate and the controller's work.
Each arm's observed maximum forecasts its future active-call cost. The native
first-call estimate additionally includes observed process startup and shutdown.
All samples, native frames, results and calibration startup/shutdown are retained.

The same optimistic gate is applied to NDU, DP and greedy. Native process
startup is lazy and occurs only after an admitted invocation. The caller
reserves the current estimate once from the continuation budget, records it as
an estimate rather than measured sunk work, and replaces the reservation with
actual elapsed service cost at the next observation. Controller work, gate
work, loader activity, execution, probes and shutdown remain in actual service
totals. The independent oracle audit is recorded separately for every arm.

Calibration costs are disclosed once in campaign preparation, with measured
per-arm attribution and the remaining shared harness cost. Shared compilation,
training, rejected proof work and historical native bridge build evidence are
kept separately. These measurements do not close complete engineering or
energy costs. Zero NDU invocations cannot be described as a successful native
NDU decision; report the invocation count alongside any gated-policy result.
Acceptance separates a gated caller-policy service win from an NDU service
win: zero-call timing wins can set only the former. A nonzero invocation count
alone establishes neither win; every registered strong-control comparison must
also pass, and whole-lifecycle benefit remains unestablished.

## Reproduction

The original `c4a1bbed3a39beba43a6abf1a18b6f75c5725c21` Rust stream evaluator
is required; the ranking and finite profiles are different binaries. Use
`tools/build_hia_recursive_ndu_bridge.py` with that exact clean upstream source
to produce the binary and `identity.json`.

```sh
python -m unittest tests.test_hia_ndu_stateful tests.test_hia_native_ndu
python tools/qualify_hia_ndu_costed.py \
  --bridge /absolute/build/native/hepta-hia-ndu-bridge \
  --identity /absolute/build/identity.json \
  --output /absolute/new-evidence-directory \
  --expected-source FULL_COMMITTED_HEPTA_SHA
```

The costed native qualification retains six models at horizons one, three and
four, both full enumeration and dynamic-frontier requests, and twelve original
native responses. Every winning prepared-set sequence and Q32 value must match
the independent exhaustive oracle and resource-aware DP. The qualification
refuses source drift and keeps `authority=DENY_ALL` and
`safety_certificate=false`. It reports only finite model agreement.

## Full-cost v2 controller return-time guard

The separate `hepta.hia.ndu.full-cost.v2` advisory controller checks elapsed
decision time again after native evaluation and response projection. At or
beyond the supplied remaining `budget_ns`, it withholds an optional invoke
action, retaining the existing skip action when model-feasible or returning
refusal. No new artifact is acquired by that fallback. Native responses and
measured costs remain in the ledger; `optional_action_withheld` and the original
projection reason distinguish a valid but late reply from a native failure.
The fallback action remains the original model skip forecast; live session
residency is read from the controller/session snapshot, not that forecast.

This is cooperative admission at return time, not preemption of native work or
a hard real-time guarantee. A timely reply does not prove that subsequent
proof, loading, delivery or cleanup will fit their estimates. Keeping an
admitted incumbent after overrunning the decision budget does not establish
that baseline delivery can still meet the original deadline. Historical native
observations and model thresholds are unchanged.
