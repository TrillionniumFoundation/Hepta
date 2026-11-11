# Original r1 HOLD and explicit scope correction

This is the original execution of frozen candidate
`f6893c2691e4038f924e44950c4ced845532ad0b`, tree
`48dcabdc2ddc0bd2211ddd3ff68c38832192eef3`. All 53 source generators reproduced
their frozen declared bytes. The three remaining source commands succeeded.
All 682 declared-source-plus-contract snapshots were unchanged after the run.

The complete selected suite actually executed **39 methods, with one failure,
zero errors, skips, expected failures or unexpected successes**. The suite took
162.671 seconds; the complete controller took 209.7852916259999 seconds. Its
terminal status is HOLD, not a passing source qualification.

The one failure is the original
`test_native_component_step_requires_original_loaded_ids_and_zero_anomalies`:
its exact module tuple still required the previous five native modules, while
the workflow correctly added the complete wire-cache and CLI modules. The
repair keeps all five in their original relative order, requires both new
modules too, adds the CLI cold binding and independent cache/CLI fixture paths,
and checks preservation of their artifacts and the encoding caller evidence.
The same original test ID and all ten original synthetic failure modes remain.

## Incorrect original scope field

The r1 controller accidentally selected the whole
`tests.test_hia_selfhost_contract` module instead of the source-only
`SelfhostContractTests` class selected by the actual CI source workflow. It
therefore also executed the one original `SelfhostColdReplayTests` method.
That method actually passed. The original report's
`cold_or_native_caller_qualification_executed: false` and `SOURCE_ONLY_NOT_COLD_OR_FULL`
labels are consequently inaccurate descriptions of this run and must not be
used without this correction. The raw report and original frozen controller
are preserved, not rewritten to hide the mistake.

The cold method used its unchanged 180-second wrapper and 38-phase contract.
Its own temporary-directory context removed its final cold fixture after the
assertions. A separate read-only observation copied 3,300 stable JSON/log/image
files while the run was still active and its phase index showed 28 completed
phases. The copies are labelled as a live partial observation. They do not
contain the final complete cold report, all phase archives or a terminal
independent custody attestation. This cold self-test pass is therefore **not
promoted to retained current-source cold qualification**. The full candidate
still needs its explicit complete cold gate and full regression.

The corrected source controller selects the same source-only class as CI.
Its intended source denominator is 38. The excluded cold method is unchanged
and remains mandatory in the full retained discovery; no product, cold, CI or
full-regression test denominator has been reduced. A subsequent controller run
has its own pre-execution source identity and output directory. It cannot
overwrite this HOLD or its evidence-custody limits.
