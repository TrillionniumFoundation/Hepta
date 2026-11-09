# Prepared NDU cost-interval replay repair

The previous replay could accept a campaign cost of one nanosecond despite
retaining 72 successful serial cells. It also accepted a declaration that
nested cells were charged again, a negative queue delay satisfying the old
caller/service equality, and a call timer longer than its enclosing cell.
`counterexamples.json` records all four cases: source commit
`20eace37747fde9aa0fc9c14cdb0159db30f5161` accepts them and this candidate rejects them.

The repair checks exact nonnegative queue durations, positive measured
service/caller/call/cell/campaign durations, the caller = service + queue
identity, and containment of each serial interval in its enclosing interval.
Preparation and close remain inside the prepared cell. Nested timers are
compared as bounds and are not added to their outer timer again. Outer
bookkeeping is permitted; the timer hierarchy is not an exact decomposition
or independent authentication of clock readings.

The original final archive is unchanged: 262,840 bytes, SHA256
`6f5017ea1de8708e304caa02988d6cf176b3a29df35bbc05881317d7687ffdd7`.
Its original 72 cells, 1,020 native observations, 510 ordinary calls, and 510
paired identical native stdout values still replay successfully. The new
regressions re-read those retained bytes in memory; no timing campaign or
upstream native evaluator was rerun. The separate transport tests execute
controlled executable fixtures and do not establish upstream NDU provenance.

Validation: `python3 -B -m unittest tests.test_hia_release
tests.test_hia_ndu_prepared_ranker tests.test_hia_ndu_prepared_cost_intervals -v`
passed 54 tests with zero failures, errors or skips. The first full attempt
had 15 errors because the sparse checkout omitted unchanged
`rust/hia-ndu-bridge/upstream.json`; its original log is retained. Restoring
that source fixture produced the successful run without changing product
code. An initial support-contract check similarly stopped at omitted
`examples/hia_bootstrap/bytesum.hiaasm`; after restoring the unchanged example
directory, `generate_hia_selfhost_contract.py --check` passed for all 251 files.

The new regression module and existing archive are explicitly registered in
the release candidate inventory. The archive's directory is included in the
declared materialization source closure so the registered test does not lose
its fixture after a public materialization. The existing NDU integration
workflow now runs the new module. No default release lock is changed here.

To reproduce the four old/candidate results from this source checkout:
`python3 -B review-evidence/hia-ndu-cost-intervals-20261109/reproduce.py`.

P2 acceptance remains **HOLD**. This validates internal arithmetic of supplied
measurements. Full acquisition, build, engineering, provider, monetary and
energy costs remain incomplete. The historical ordinary control remains
faster with the same selections; no stable NDU economic advantage is claimed.
