# Paid-observation failure custody — 2026-11-09

The runner now retains original databases, durable owner-bound intent/result
journals and atomic checkpoints when execution is interrupted. It refuses an
existing campaign directory or cell journal and never automatically replays an
unknown effect. The original two-second protocol is unchanged. A further
admission check recomputes remaining time after the intent's flush/fsync.

## Retained attempts

| Fresh attempt | Test methods | Result |
| --- | ---: | --- |
| Unchanged recovered source: original failing test bodies | 3 | PASS |
| Deterministic deadline counterexample before the guard | 1 | FAIL |
| Same counterexample after the guard | 1 | PASS |
| Complete suites on local source `4b5e530176934b7210a7a328f24836301eb52ee3` | 12 | PASS, zero skips/errors/failures |

The original earlier 11-test development attempt's three failures remain in
`PRIOR_FAILURES.json`. That file is a labelled transcription; those original
per-case temporary fixtures were not retained. Their causes remain UNRESOLVED,
and the executor outage is not established as their cause. Later success does
not erase them. The separately found deadline defect has its own before/after
counterexample; this controlled-clock test uses a forbidden-dispatch mock and
is not a native timing observation. Both real post-effect tests explicitly
verify their effect/commit preconditions before injecting interruption.

`retained-attempts.tar.xz` preserves the four fresh attempts, driver logs and
exit markers, source snapshots, databases, journals, and the recovered R2 audit.
It is 65,320 bytes, SHA-256
`3e11b8a5baaa750e1b6329b89b184ecc0fd219cced0f89ac145a6be974473974`.
All 367 files indexed by its `FILE_INDEX.json` were read back and verified.
Campaign controls retain complete owner/source/protocol/result capsules.
Direct unit controls without a journal retain their database and assertion
output; their in-memory return objects were not separately persisted.

The recovered original audit's stdout and report record PASS for 8 calibration
databases, 30 heldout databases and 41 worker events, with zero producer
imports/executions or subprocess invocations. Original session 17910 is no
longer available, so its exit status stays UNKNOWN. It was not rerun.

## Actual normal pilot in the 12-test attempt

`PILOT_RESULT.json` is the exact result (SHA-256
`24df09045b87302b1876e1b53f54957ae1348749e89492e8018ddc122fc9ae37`).
It reports PASS_MECHANISM for 8 calibration reads, all 30 cells and 49 worker
records. The maximum observed cell interval was 0.219039061 s, below the
unchanged 2,000,000,000 ns limit.

| Control | Delivered / observed | Failed read / STOP controls | Synthetic fee | Synthetic score |
| --- | ---: | ---: | ---: | ---: |
| Fixed | 8 / 10 | 1 / 1 | 23 | 57 |
| VOI | 8 / 10 | 1 / 1 | 21 | 59 |
| Complete enumeration / MPC | 8 / 10 | 1 / 1 | 21 | 59 |

VOI and the strongest complete finite control remain equal. The partition is
known and synthetic, not independently author-blinded. No trained/native NDU
policy or real Agent/provider was used. NDU is NOT_RUN with zero policy calls;
P5 remains HOLD.

The pilot's enclosing wall interval was 4.738800369 s, including calibration
0.816035043 s and fixed fit 0.000287447 s. Nested intervals are not added again.
The entire separate 12-test attempt took 7.359357186 s, with parent CPU
0.486724 s and child CPU 6.083747 s; these CPU counters are not assigned solely
to the normal pilot. The campaign explicitly excludes outer interpreter
startup/imports and final result encoding/write. Terminal cell receipts and
campaign checkpoints are outside the registered cell interval but within the
enclosing campaign, apart from its final write. Synthetic units are not money;
full billed cost remains unknown.

## Publication scope and exact history

`BASE_SCOPE.json` records the exact split: the prior cf862 commit inherited
110 changed files from 2e2afc1a, comprising 91 paid files and 19 other P1/P2
paths. The paid-only publication imports the full 91-file paid baseline,
including both unchanged original evidence directories, and adds the retention
work and its evidence. The other 19 active changes are excluded. The producer,
independent auditor and tests have only standard-library dependencies.

The full original local Git history is retained separately in the bundle and
publication provenance. The published tree is a paid-only projection on 2e2,
not a whole-tree equivalence claim to cf862 or the local qualification tree.
The 12 tests establish no adoption-projection/P1/v2 integration.

## Explicit hosted gate

`tools/qualify_hia_paid_retention.py` requires the exact 12 test identities,
zero skips/errors/failures and the same clean expected source before and after.
It retains all temporary fixtures. Give it a fresh output directory outside the
checkout and an explicit `--expected-commit`; the accompanying workflow does
this for the actual push or PR head. Hosted CI has its own evidence and cannot
inherit a local or earlier-head result.

Existing output inspection uses
`qualify_hia_paid_observation.py --inspect /absolute/original-evidence`.
Inspection never authorizes replay. Historical output without the new owner
capsule does not acquire one through this command.
