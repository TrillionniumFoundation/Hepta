# Exact summary types and sparse CI source

Independent review confirmed the attempted-end containment fix and identified
three further Python equality aliases: a float end offset in SUMMARY.cells,
or float completed-pair/native-call counts, could equal the original integer
records and pass. Both the original-cell comparison and every recomputed
summary-field comparison now use canonical JSON. The old accepted records,
unchanged independent script, final four refusals and complete original
archive positive are retained in `independent-*.json` and the corresponding
script. They bind the actual checker SHA256 values.

Final code commit: `0a94008849433997e0c70ad7b321f2895b293d9c`, tree
`b1a3fd9dcc63eb58b73b9a63e1e0ff8514978a97`.
Final checker SHA256:
`a8bc7f8b97cb01f3be41a59cf926adcbcb88a1c8d94cc18cf647414526d28961`.

The complete scalar module now passes **19 tests**, zero failures, errors
or skips, in 0.875 seconds, using the same sparse source directories as the
independent scalar workflow. The exact-source CI count is 19, and its error
message refers to the named test set. The scalar workflow's sparse checkout
now includes the existing original-campaign archive directory required by
the new raw evidence regressions. The integrator's original missing-fixture
failure remains retained separately; no source fixture is replaced.

The earlier 18-test log and first-stage checker identity remain historical
records. `final-tests.log` and `final-red-green.json` record the final source.
The unchanged original archive remains complete: 128 cells, 64 pairs, 64
successful original native calls and 307 objects. Independent review starts
zero native processes. These checks do not run a new benchmark or provider
call, and the economic conclusion remains HOLD.
