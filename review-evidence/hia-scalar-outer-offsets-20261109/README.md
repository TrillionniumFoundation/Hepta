# Scalar call offsets must fit inside the reported outer interval

PR #824 review `4509542158` identified an accepted inconsistent cost record.
The unchanged original campaign records 943,383,830 ns of summed call
durations, but the final attempted call ends at offset 1,280,472,124 ns.
Changing the reported outer duration to the sum and overhead to zero kept
the old sum equality true while ending the outer interval before that call.
`red-green.json` preserves the old acceptance and corrected refusal.

The fix checks all three outer cost fields as exact nonnegative integers,
then requires every attempted call's end offset to fit within the outer
duration. `results_summary` already checks each attempted row's exact
nonnegative offsets and duration, including failed calls; the outer check
uses that same denominator. Unstarted calls keep absent observations and
are not invented zero-duration attempts. The original non-overlap and full
sum/overhead checks remain active.

The actual producer uses `time.monotonic_ns()` for the outer start and each
call's start/end offset. The outer endpoint follows the final identity,
source-state and evidence work. Thus the containment condition applies to
successful and failed calls even when the campaign remains INCOMPLETE.
This audits reported intervals, not hardware-authenticated clock truth.

Code base: `9ba2a6202277e3d3418d3a8205450973174eb812`.
Code fix: local `d045e14dd691c2bc06177e428402c3e65d6e4af5`, tree
`60b1e5f1614a24530e699572991d0cb26a3b1171`.
Old checker SHA256: `dd72d54536836ff6b254bb1606ade718660d489022c70336f9fb0b1dd19fdd47`.
Fixed checker SHA256: `f6c56e9be0da978e692351c75d06ef8051b4bf4c60280bb286f3673a4a28d114`.

The original 1,283,026-byte archive is unchanged, SHA256
`d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d`.
All 443 members pass ZIP CRC. Its 128 cells, 64 completed pairs and 64
successful original native calls still verify, including all 307 objects.
Three additional mutations replacing cost integers by Python-equal floats
also passed the old checker and are rejected by the fixed checker.

`python3 -B -m unittest tests.test_hia_scalar_controller_controls -v`
passed **18 tests**, zero failures/errors/skips, in 0.845 seconds. New tests
cover the original archive, the review counterexample, exact measurement
types, completed and failed attempts inside INCOMPLETE campaigns, exact-end
positive boundaries, one-nanosecond understatement refusals, and all-unstarted
campaigns with absent call costs. The existing exact-source workflow's
required test count is updated from 12 to 18.

Reproduce the original/fixed record comparison with
`python3 -B review-evidence/hia-scalar-outer-offsets-20261109/reproduce.py`.
The script and regression tests read original retained bytes in memory;
no native evaluator, provider call or timing benchmark is run.

The original head and review remain part of history. P2 economic acceptance
remains HOLD: internal timing consistency does not establish real-task
incremental value, complete external costs or stable economic benefit.
