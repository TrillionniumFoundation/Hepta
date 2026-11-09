# v14 integration: preserved identities, deadlines and original evidence

This preparation combines the complete published PR817 integration and PR819
trees. It changes three conflicting Python fixture files and retains the
remaining source and historical evidence from the appropriate published parent.
It does not publish a ref or substitute parent validation for CI on the new
integration head.

| Role | Commit | Tree |
| --- | --- | --- |
| First parent, PR817 integration | `2aa206882c7d6298d74ddc1ddf3a4ccb052e41a6` | `a8da053838224575cbb5490a321b83d060bb7c75` |
| Second parent, PR819 v14 | `635c57bd7fd0b9f37480b4da091af4dddfd53a36` | `f696b321aa98dcfa183fc72be67904b06eef0424` |

The complete source tree before adding this report and its evidence package is
`9ff1b36fb59858145e0d46010289a15fb91a3437`. All validation below identifies this
prepared source and records the relevant source SHA256 values before and after
execution. The original published checkouts were left unchanged.

## Complete parent provenance

Relative to the first parent, the prepared source has 38 changed paths: 35 reuse
PR819 blobs exactly, and three contain the reconciled fixtures. There are no
deletions. Mechanical tree and byte checks retain the full union of parent
paths, including the five PR817-only evidence paths.

The eight overlapping paths with different parent blobs are resolved as follows:

| Paths | Integrated choice |
| --- | --- |
| `tests/test_core_seven_part04_capture.py` | PID/starttime identity from PR819 plus all PR817 cleanup, group and timing checks |
| `tests/test_core_seven_relocation_runner.py` | Both timeout modes and configurable checkpoint readiness |
| `tests/test_core_seven_relocation_timeout.py` | Both preoutput controls execute as subtests of the same existing method |
| `.github/workflows/hia-initialization-frontier-research.yml` | Exact PR817 blob, including the 723-ID disjoint-union checks |
| `docs/seven-part04-diagnostic.md` | Exact PR817 blob, including the leader/streams cleanup scope |
| `.github/workflows/hia-sixgap-source.yml` | Exact PR819 blob |
| `docs/HIA_SELFHOST_CORE_SUPPORT.json` | Exact PR819 blob |
| `tools/hia_release.py` | Exact PR819 blob |

The collector and both independent readers have identical Git blobs in both
parents and this integration. Their production process, cleanup and pending-EIO
limits remain 60 seconds, two seconds and 50 milliseconds. Byte limits, v2
receipt semantics and historical v1 handling are unchanged.

The existing u16/v14 work and original-output fragment qualification are
incorporated as PR819's exact bytes. They were not executed locally during this
fixture reconciliation. Their original evidence and scope statements remain in
the inherited reports.

## Bounded observation of the known descendant identity

The real harmless Python fixture reports its child PID and Linux start time.
The observation loop parses fields after the final closing parenthesis in
`/proc/<pid>/stat`, then compares that start time before treating a later PID
observation as the original child. The process-group assertion applies only
while the original identity still matches. A reused PID belongs to a different
identity and cannot be charged with the original child's group membership.

The existing collector-duration assertion remains. The complete observation
uses the same fixed `started + 1.5 seconds` deadline, set before capture. Every
read is followed by a monotonic-clock observation; a late result fails even if
it reports a zombie, disappearance or replacement identity. A matching identity
must become `Z`, or the original identity must disappear, before that deadline.
Persistent live observations do not pass.

The method still requires real `group_kill_sent`, `leader_reaped`,
`drain_complete`, no `cleanup_incomplete`, and no
`cleanup_deadline_exceeded`. It logs the original PID/starttime, process group,
state changes and elapsed time. Each state record is
`[elapsed_seconds, state, same_identity, observed_starttime, observed_group]`.

These checks concern this known fixture identity. The production receipt still
describes the owned leader, captured streams, signal result and deadlines; it
does not establish that every descendant in an arbitrary process tree has
exited or been reaped. The inherited scope documentation remains unchanged.

## Both timeout fixture modes remain exercised

The relocation fixture accepts `timeout_mode` and `timeout_ready_seconds`.
Default checkpoint mode waits for all eleven marker records to be appended and
fsynced, with its existing finite five-second readiness guard. Cleanup advances
in real time. The explicit elapsed mode preserves the earlier process-only
clock acceleration while also keeping cleanup in real time.

The existing preoutput method now executes two subtests: elapsed mode with the
ordinary readiness parameter and checkpoint mode with PR819's 0.1-second ready
guard. Both retain the 0.7-second child startup delay, zero-marker requirement,
zero observed stdout/stderr bytes, replay assertions and original cleanup
checks. No test-method ID is added for these subtests.

## Fresh, narrow local validation

The selected suite executed eight methods in one run, with zero failures,
errors, skips, expected failures or unexpected successes. Unittest reported
41.241 seconds; the retained wrapper measured 41.410937 seconds including suite
loading. Both preoutput subtests are individually recorded as PASS.

| Selected methods | Count |
| --- | ---: |
| Known descendant identity and actual cleanup receipt | 1 |
| Existing relocation cleanup/preoutput controls | 3 |
| Original failure replay and delayed-marker timeout replay | 2 |
| Durable-marker clock and finite readiness-guard controls | 2 |

Four additional invocations of the single descendant method inject explicit
read observations after its genuine Python collector call:

| Injected observation | Required method result | Control result |
| --- | --- | --- |
| Different start time and different process group | Accept disappearance of the original identity | PASS |
| Original start time but different process group | Reject the group mismatch | PASS |
| Original start time and persistent `R` | Reject at the original total deadline | PASS |
| Replacement identity returned after a 1.51-second read delay | Reject the late observation | PASS |

These are one positive control and three intentional method failures checked
for their specific reasons. They are not four new CI IDs, four ordinary green
unit tests, or a reproduction of real PID reuse or the earlier kernel timing.
Original receipts, raw stream/event bytes, actual read contents, delivered
observations, injection labels and times are retained separately for each case.

Inventory verification executes no test methods. It confirms that the original
709 IDs remain, PR816's three additions produce 712 IDs, and the eleven
independent deadline controls are disjoint, giving exactly 723. Capture remains
41 methods, Part04 runner 17 and relocation runner 23. The initialization
workflow is the exact PR817 integration blob.

No compiler, native loader mutation, solver or full 108-method suite was run
during this reconciliation. The selected run, injected observations and
inventory check are separate evidence, not additive counts of unique tests.

## Two different historical failed runs remain intact

The PR817 integration's first 108-method attempt remains **107 passes and one
failure**, zero errors, in 260.525956 seconds. Its failed immediate descendant
state observation, subsequent bounded correction and directed observations are
retained in `HIA_PART04_FIXTURE_INTEGRATION_20261109.md` and its original package.
The precise cause of that individual failed sample remains unresolved.

PR819 retains a different 108-method attempt at commit
`4689f80a833b48d9615d0400cb6c993990d1d4f5`, with **one failure and one error** in
229.925 seconds. Its original log, execution record, descendant observations
and follow-up reports remain under
`review-evidence/part04-descendant-exit-20261108/`. PR819's own report describes
the separate source-inode error and subsequent unchanged-source validation.

Neither original result is removed, merged into the other, or replaced with
this narrower run. The historical reports describe their own source versions;
this document records the additional identity/mode reconciliation.

## CI observations and remaining qualification

The archived readback records 19 successful workflows for PR819. At that same
snapshot, PR817 integration `2aa20688` had 18 successes and its native NDU
workflow still in progress, without retries or cancellation. The exact-source
workflow for `2aa20688` had already succeeded.

For the 19 PR817-associated workflows, 17 explicitly select the head commit.
The Linux native contract and Safe Core jobs used prospective-merge commit
`53dd0caab79205e84ebbe3642846a2c9cab604d5`; its tree equals the first parent's
`a8da0538` tree. Their retained artifacts report that merge commit. They are not
relabeled as having checked out the head commit itself.

Parent results do not qualify the new integration head. The resulting published
head must pass its own applicable CI. This fixture reconciliation does not
establish complete Core self-hosting, general compiler/ABI/resource/FFI/ISA or
loader correctness, original Agent evaluation/adoption, full provider billing,
or stable NDU economic benefit. Existing HOLD conclusions and proof assumptions
remain in force.

The machine-readable provenance, exact selected method IDs, full raw logs,
injected-observation records, inventory and archive hashes are in
`review-evidence/hia-v14-fixture-integration-20261109-e5ee/`.
