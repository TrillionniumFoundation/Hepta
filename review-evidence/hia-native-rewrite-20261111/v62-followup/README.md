# v62 follow-up: retained failures, dispatch tests and fixture construction

This continuation starts from published commit
`d6847ac891e0dd07217d179891bb763162211de2`. It does not qualify that failed
source, any later source, or the complete HIA-native product. The production
JSON scanners, their native diagnostic ABI, cold deadline, two-worker budget,
phase inventory, actual consuming references and original test methods remain.

## Original full retained qualification failure

`v61-failed-qualification.tar.xz` contains the complete frozen independent
readback directory for commit `647885c5c3ff067b6477011123335ad5a1aef78e`.
Its nested `raw-qualification.tar.xz` has 96 original top-level or explicitly
bound members, 7,098,304 uncompressed bytes, and SHA-256
`a26741291b2cab96f3a39ae46a449888e0d02da67178f4ffc8b7e226fbbefbd4`.
All member bytes, sizes and modes were independently replayed after fixed-version
chunked download. Full source snapshots match all 2,587 Git blobs and modes;
the harness and original source were preserved.

The final outcome is **HOLD**, 21/22 workflow steps passed. Full retained
regression ran 3,954 tests with one failure and no errors, skips, expected
failures or unexpected successes. Its 746,143-byte stderr is complete. The
earlier cold replay passed 11/11 checks in 95.954178227 seconds, which does not
override the later failure. Nested cold/runtime/reproduction directories remain
on the original execution host and are explicitly outside this top-level package.
Original RPC timeouts and same-key reconciliation records are retained.

## Original published v62 GitHub failure

`d684-github-observation.tar.xz` retains original job logs and metadata plus the
scoped analysis for run `42962692808`. Source tests passed: 278 tests in
254.367 seconds. Native cold replay failed at 180.156933097 seconds, 6/11
outer checks, 34/38 completed phases, 3,758 true and zero false checks in those
completed reports. Names/exports phases without final reports are not passes.
Cleanup completed in 61.809195 ms with ECHILD and no remaining children/errors.

The original failure ZIP is artifact `13830101641`: 46,307,599 bytes, SHA-256
`345ea7e8635b6a4603e56eb6fa3f638bc2241e385983652bcb01fb4770929db6`.
It is retained separately in full. All 570 source entries match the exact
published Git objects. The analysis verifies completed phase reports, their
inputs and the compressed nested archives against receipts; it does not claim
a new replay of every nested raw member. Neither the original failure ZIP nor
private download URLs are rewritten into this small analysis package.

## Strict JSON dispatch regression correction

`json-dispatch-fix.tar.xz` keeps the first 26-test validation and its exact
patch/source pins. Independent review then found that a dynamically discovered
empty child suite could satisfy `0 == 0`; this is preserved in
`json-dispatch-independent-review.tar.xz`.

`json-dispatch-fix-r2.tar.xz` contains the final correction and complete
26-test, 21.292-second successful log. Parent and child both require a nonempty
suite, exact current IDs/count, and zero errors, failures, skips, expected
failures or unexpected successes. Both the detailed independent reference
diagnostics and the unchanged selected native generic diagnostic are asserted
explicitly. The native selector is not suppressed. The full original native
preflight module is now present exactly once in the actual native CI step.

The independent r2 review confirms all nine host test methods, thirteen native
test methods, seventeen detailed error inputs and the original no-fallback,
missing-manifest, budget and duplicate controls remain. Native scanner,
generator, adapter and public dispatch production bytes are unchanged. The
original full-suite failure is not relabelled as a pass.

## Pure batched fixture construction

`batch-fixture-development.tar.xz` retains complete old/new invocation ledgers,
complete reference bytes, the candidate patch/sources, fourteen-test successful
regression log, and all four fresh-process 17-family panels with original worker
receipts and source manifests. `batch-fixture-independent-review.tar.xz` contains
the separate static-boundary review and independent original-ledger replay.

All 1,420 actual public calls match in original order: 710 Core checks,
346 VM executions and 364 public assemblies. The complete signed/cast reference
is identical at 5,808,503 bytes, SHA-256
`d58330121ae82ece2364366ffe8c11aac8080164156bf1c846e5b76c2940060e`.
There remain 52 signed and 58 scalar-cast batches, 236 traps and 18 refusals.
Only 506 Core calls and 396 assemblies used for intermediate construction were
removed. No VM execution was removed.

The utility now constructs unverified syntax. It intentionally does not promise
the old early semantic rejection of arbitrary malformed intermediate inputs.
Every actual final fixture still traverses its complete original public admission
and VM observation. The bad-helper negative control checks that boundary. Grouping,
rebasing, constant sharing and the original capacity checks are unchanged.

Every full panel is identical at 13,726,901 bytes, SHA-256
`805cb0d0ea1a32dfb4262b7b2d2f0e4e7460fd8ca89c7a1665e25645db3a0b60`.
Baseline observations were 30.501287 and 27.590464 seconds; candidate observations
were 26.281226 and 26.351774 seconds. Development work overlapped in this shared
environment. These measurements do not predict a specific CI runtime and do not
constitute cold qualification. No result, verified program, child process or
admission authority is reused across qualification observations.

Each outer package has a complete adjacent custody manifest. Its compressed
bytes and every outer member were checked after writing. Development artifacts
retain their original source identity, including intermediate review revisions.
