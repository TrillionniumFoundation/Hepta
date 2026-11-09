# Persistent NDU cost-interval replay repair

The persistent campaign's outer timer begins before all serial cells.
Each cell starts its timer before creating either native owner and records
its final duration after the owner's close. Each call timer contains the
owner's `rank`, selection checks and original-result bookkeeping. Each owner
records its caller interval inside `rank`, with service and queue subintervals.
These concrete intervals justify the containment checks added here.

The replayer now requires positive exact campaign, cell, call and caller
durations, nonnegative exact queue delays, and caller = service + queue.
Every serial call must fit its cell; the owner preparation, caller intervals
and close must fit their cell; all cells must fit the campaign. Outer
bookkeeping is permitted. Nested timers are compared as bounds rather than
added to their enclosing timer. This is internal consistency, not host clock
authentication, a hard real-time reservation or a full lifecycle cost claim.

The paired analysis was already recomputed numerically. Its final comparison
now uses canonical JSON so booleans and floats cannot silently substitute for
integer identifiers or booleans through Python's `True == 1 == 1.0` equality.

The unchanged original archive has 400,748 bytes and SHA256
`7f46424cdfb8171650bcf77dfb9b0c25412b4e877c413a90a9108b7604cd8cfd`.
All 72 cells, 510 prepared processes, 24 persistent processes, 1,020 native
responses and 510 ordinary calls still replay. The source, frames, cleanup,
selection and original paired-response byte checks remain active.
`counterexamples.json` preserves eight mutations accepted by the original
replayer at public commit `20eace37747fde9aa0fc9c14cdb0159db30f5161`
and rejected by this candidate. No new upstream native execution or timing
campaign was performed. The first reproduction used local source-equivalent
parent `b67970e4`; its result remains separately retained. The final script
uses the public commit so another checkout can reproduce it.

The new module has 12 tests. The complete local command passed 85 tests with
zero failures, errors or skips in 6.351 seconds:
`python3 -B -m unittest tests.test_hia_release
tests.test_hia_ndu_prepared_ranker tests.test_hia_ndu_prepared_cost_intervals
tests.test_hia_ndu_persistent_ranker.PersistentRankerTests
tests.test_hia_ndu_persistent_cost_intervals -v`.
The existing persistent transport class executes controlled fixtures; the
three separate tests requiring an original native build were not selected.
They remain required by the existing CI integration workflow.
`generate_hia_selfhost_contract.py --check` still passes for all 251 files.

The new module and original archive are included in `CANDIDATE_FILES`, and
the archive directory is added to the materialization source closure.
The existing NDU integration workflow includes the new module.

To reproduce the old/candidate results:
`python3 -B review-evidence/hia-ndu-persistent-cost-intervals-20261109/reproduce.py`.

P2 acceptance remains **HOLD**. The retained measurements still show the
ordinary exact scalar control faster in every pair with identical selections.
General task value, provider charges, energy, acquisition, build and complete
engineering costs remain unestablished; neither transport repair establishes
NDU economic benefit or authorizes production activation.
