# Controller guard for a late native decision

The controller already checks the budget before optional search, process startup and native invocation. A native response or its projection can nevertheless finish after the remaining decision budget. Before this change, an otherwise admissible late proposal could still return an `invoke` action that acquires artifacts.

After recording the complete observed decision wall time, the controller now withholds an `invoke` action when `wall_ns >= budget_ns`. It returns the previously admitted incumbent `skip` action if one is feasible, or `None` otherwise. This is a stricter dispatch check; model objectives, candidate generation, native protocols and performance acceptance thresholds do not change.

The proposal is still valid evidence of what the native evaluator returned. The guard retains the original `bundle` and `response`, `native_matches_exact_model`, measured phases and the original reason. `reason_before_budget_guard` and `optional_action_withheld` explain why the returned execution action differs. It does not rewrite a native witness to look like the fallback, erase an incurred invocation, invalidate a receipt merely for arriving late, or authorize an artifact that was not independently admitted.

This check uses the decision's final wall-clock snapshot. It is not a proof that the incumbent can still meet the original deadline, nor a bound on operating-system scheduling or the caller's later execution. The caller continues to own execution, resource admission and cleanup. The native session lifecycle and resource ownership rules are unchanged.

## Validation

`tests/test_hia_ndu_controller_deadline.py` uses deterministic synthetic clocks and controlled responses. It checks equality and overrun boundaries, projection cost, a valid resident incumbent, refusal when no incumbent is feasible, an existing session, native refusal cleanup, timely advice and exact preservation of the native response and proposed witness.

The same regression tests were first run against the unmodified lazy-witness controller: eight tests produced seven failure entries (including separate equality/overrun subtests), with no errors or skips. After the fix, all 54 tests across the deadline, cost model, model snapshot, current profile and lazy-witness suites passed with no errors or skips. Before/after source and test hashes and original test logs are retained in `benchmarks/hia_ndu_cost/deadline_guard_20261104/`.

These are controller correctness checks, not native performance measurements. The earlier fixed raw-model service campaign remains tied to source `99d4cb5942755ba12e1d3006558bb53d435734d8`; its measured negative NDU/DP result is unchanged in the archive. The combined composition must qualify its own final source identity.
