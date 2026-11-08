# Prepared replay: reject false paired timing analysis

The prepared replay at Hepta source
`50c1578b4d4597e3070a9abc3700c9aacbf99851` checked original requests,
responses, cell identities and disjoint owner costs, but did not compare
`result.json.analysis` with the retained cell timings. This reproduces and
repairs [review comment 4507258712](https://github.com/TrillionniumFoundation/Hepta/pull/808#discussion_r4507258712).
The scope is evidence integrity. P2 remains `HOLD`.

## Actual original-data counterexample

The input is the complete prepared campaign from public CI run
[42516119809](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42516119809),
artifact `13631367936`, original ZIP SHA256
`4b13273fc3dd4208e312803f369075603435e9f0e17cccb74099f727d9248ed2`.
All 160 prepared members (16,206,689 bytes) were retained in two independent
directory copies. All non-result member hashes were rechecked unchanged.
Registration SHA256 is
`79536136c58662d8ff35e7fd747a7c3c077fa157d6982c946f6c377e8b1927dd`.

Only two fields in the counterexample report were changed to
`-999999999999999999`: the first pair's `one_shot_minus_prepared_ns` and
that horizon's summary `sum`. The complete original measurements, cell
ledger, individual cells, all original frames, source copies, build receipt
and registration were unchanged. The original verifier accepted both
directories and returned `raw_identity_and_cost_arithmetic_consistent: true`.

| Exact input | Original verifier | Patched verifier |
|---|---|---|
| Unchanged complete CI campaign | Accepts, exit 0 | Accepts, exit 0; all reported analysis recomputed |
| Same campaign with the two false report fields | Incorrectly accepts, exit 0 | Rejects, exit 1; no successful replay receipt created |

`original-reproduction.json`, the two `old-*-replay.json` files and their
original stdout/stderr preserve the erroneous acceptance. They are historical
counterexample observations, not valid qualification of the altered report.
`original-result.json`, `counterexample-result.json` and `mutation.json`
preserve the precise before/after report bytes and field changes.

## Minimal repair and controls

Only `tools/replay_hia_ndu_prepared_ranker.py` and its existing test module
changed. After all existing original-data checks, the verifier now rebuilds
the exact 72-cell denominator, 24 paired comparisons, three arm costs per
pair, both pairwise cost differences, all completion flags and every horizon
summary. The eight summary fields are observation count, sum, mean, median,
minimum, maximum, sample standard deviation and positive-pair count.

The full rebuilt parsed JSON structure must match the reported analysis.
Canonical JSON comparison retains list order, complete field sets and number
types; Python's implicit equality between `true` and `1`, or between `1.0`
and `1`, cannot admit a changed report. Source and raw-frame validation,
native byte equality, cost ownership and authority checks remain in place.
Successful replay now explicitly records `reported_analysis_recomputed: true`.
No production evaluator, timing runner, registration, request, measured cost,
ranking rule or persistent replay was changed.

All 23 tests in the prepared test module passed, including eight new test
methods and 204 negative subcases. The positive fixture has hand-calculated
losses, a tie and gains; it does not select only faster pairs. Negative controls
change every pair's individual cost, both differences and completion flag;
each of the eight statistics at every horizon; report shape/order/identity;
equal-looking Python number/boolean types; ledger identity, completeness and
positive integer costs; and a ledger cost while retaining the original report.
The actual complete CI directory and the same actual counterexample were then
replayed with the fixed CLI. `fixed-validation.json` and the retained command
streams bind these results to the exact patched source hashes.

The patched original-data replay retains all 1,020 native calls, 510 ordinary
calls, 510 identical paired native response bodies and 72 cells. Replaying
evidence did not execute the native evaluator or resample any experiment.
The existing transport unit tests use controlled fixture processes; those
are not new NDU measurements or provider calls.

## Complete inputs and reproduction

The full original CI bytes are retained in
`../hia-ndu-persistent-ci-50c-20261108-5e6c/raw.tar.xz`, SHA256
`544e51e235e647aa6d32f1b0360096adaddfc5e905f8cd253f1f9ed9d11df37c`.
That archive's inventory covers all 475 CI members, including every prepared
input required here. Its member hashes were independently checked against
the original ZIP. This directory keeps the small changed report and all
reproduction outputs rather than duplicating those unchanged original bytes.

To reproduce, extract the archive into a new disposable directory, keep its
`prepared-mechanism` tree unchanged for the positive replay, and make a separate
copy for the counterexample. Replace only the copy's `result.json` with the
retained `counterexample-result.json`. Run the retained `original-verifier.py`
on both directories, then the patched repository
`tools/replay_hia_ndu_prepared_ranker.py`, always passing the registration
digest above and a new `--output` path. The old verifier's false acceptance is
intentional reproduction of the defect; use the patched verifier for review.

`source-binding.json` records the exact original Git blobs, patched blobs and
review location. `source.patch` is the complete two-file change against the
50c file bytes. The later root checkpoint `d6431f233619e1339cec5532741d9303ecfcf150`
still had those same two original file identities; no repeat sampling is
needed to establish this particular counterexample.

Elapsed timings remain unauthenticated observations of the shared CI host.
All existing limits on synthetic workload scope, acquisition/build costs,
provider interactions, complete lifecycle economics and machine correctness
remain unchanged. Both replay outcomes retain `authority: DENY_ALL`,
`economic_benefit_established: false` and
`timings_independently_authenticated: false`. Correcting report arithmetic
does not establish stable NDU value or promote P2 acceptance.
