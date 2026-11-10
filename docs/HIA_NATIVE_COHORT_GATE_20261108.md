# Native benchmark acceptance: complete cohorts and retained costs

## Defect and scope

The native benchmark assessor previously built a dictionary indexed by arm for
each episode before checking the observation cohort. A later duplicate could
therefore replace an original losing NDU row. It also did not require every
row to have completed, validate the service/audit cost decomposition, or bind
the reported native invocation count to its retained steps and closed session.
An empty episode registration made the all-episode comparison vacuously true.
The finalization step checked source/runtime flags but did not recompute the
acceptance result from its final observations.

These are result-admission defects. The reproductions use explicitly authored
accounting fixtures, not measured application performance or native NDU runs.
They do not show that an existing historical campaign exploited the defects.

## Change

`tools/qualify_hia_native_ndu.py` now admits one complete matrix over the four
registered controls and a nonempty registered episode list. Missing, duplicate,
extra, failed, cancelled and unfinished observations refuse qualification. The
same validator is used for the service comparison and prepared-owner cost
accounting.

Every row must retain the exact request-step sequence, positive integer actual
and service elapsed totals, nonnegative integer audit/controller costs, and the
identity `actual_total_ns = service_total_ns + independent_audit_ns`. Audit
subtraction must equal the sum of the retained audit intervals. All retained
controller work must fit inside the charged service interval. Unknown values,
booleans, negative costs, fractional costs and nonfinite values cannot produce
a saving. The training median/p95/p99 observations and registered ratio limits
must be finite, positive and correctly ordered.

Native invocation counts must equal the retained response count. Positive
counts require a matching closed session, the same request count, complete
request-cost observations and no cleanup error. A count alone cannot qualify
NDU use. Finalization recomputes the assessor and withdraws an acceptance result
that no longer matches the final retained observations.

The registered thresholds, tasks, controls and historical files are unchanged.
The checks reconcile recorded data under the existing trusted-producer/host
contract; they do not authenticate an external provider or independently prove
native execution. A complete negative result remains negative. A faster gated
policy with zero NDU calls still cannot establish NDU benefit. Complete lifecycle
cost, stable incremental value, economic benefit and general machine safety
remain unestablished by this change.

## Validation

The original scratch environment disappeared during the task. The candidate
was reconstructed from the exact GitHub source at
`2598f4309791d3a023cd5df585ad26810b20c744` and the recorded patch, then tested
again. The retained files below are new executions after that recovery.

Running the 13 adversarial test methods against the original assessor produces
58 failing subcases and eight errors. The errors include malformed inputs that
already raised an unstructured exception; they are not counted as positive
acceptance exploits. The original-assessor SHA-256 is
`d47e76a30d1da54f490b66c06fc498c7396ffa17226ff061d99c6d30572af837`.

The final focused regression run passes 42 tests with zero failures, errors or
skips. It covers the accounting attacks, complete negative observations, the
zero-invocation rule, registered performance/tail limits, source/runtime drift
and prepared-owner cost attribution. No provider request or new performance
campaign is included. The tested candidate assessor SHA-256 is
`8337b178266974acc3b5848c232ab219d6717630cb5f4c72e3a93761bea0e230`.

```sh
python -m unittest tests.test_hia_native_cohort_gate \
  tests.test_hia_native_performance_tail_gate tests.test_hia_native_ndu \
  tests.test_hia_native_ndu_identity tests.test_hia_prepared_gate_profile -v
```

Retained evidence:

- Original-assessor red test log (historical path `../review-evidence/hia-native-cohort-gate-20261108/reproduced-red-tests.log`; not shipped in this tree)
- Recovered candidate focused test log (historical path `../review-evidence/hia-native-cohort-gate-20261108/recovered-focused-tests.log`; not shipped in this tree)
- Source identities and result summary (historical path `../review-evidence/hia-native-cohort-gate-20261108/validation.json`; not shipped in this tree)

Existing historical benchmark receipts were not rerun or rewritten; this patch
does not establish their completeness under the stronger assessor until their
original observations are supplied. The source hashes and fixtures establish
the demonstrated admission behavior, not independently authenticated economic
benefit.
