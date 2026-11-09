# Part04 fixture integration: retained failures and bounded observations

This integration combines the complete PR817 and PR816 source trees on their
common baseline. The production Part04 v2 collector and both independent
readers remain byte-for-byte identical to PR817. Fresh CI on the resulting
published integration commit remains required.

| Role | Exact commit |
| --- | --- |
| Source baseline | `ffa64c93dd4c51190fda8c0f647481a31ffbcf07` |
| PR817 parent | `164e462e6098f3a31790b8987705e7fe6592b230` |
| PR816 parent | `39ae467a5806a9c969133e6e8801f83c96f246aa` |

The final code tree before this report and package is
`4272137c5d67cfc08fd8dda26e07ae3e7af277b1`. The original PR817 checkout and
commit were left unchanged. No remote ref or PR merge was performed during
local preparation.

## Two fixtures retain two different timeout controls

Default `checkpoint` mode retains PR816's clock: all eleven marker records must
actually be appended and fsynced before the process interval expires. Its
original five-second readiness guard remains finite. Cleanup then advances in
real time.

Explicit `elapsed` mode retains PR817's process-only acceleration. It can expire
before child output while keeping cleanup in real time. The existing preoutput
control selects this mode and still requires zero markers and zero observed
stdout/stderr bytes. The two cleanup-delay controls use checkpoint mode with
their existing replay and deadline assertions.

Mechanical concatenation was checked first. The existing preoutput method
failed in 30.114 seconds with `11 != 0`: the checkpoint clock waited for markers
that this control requires to remain absent. That original failure is retained.
It establishes this integration conflict, not the unique cause of the older
PR808 CI failure.

## The first full local attempt remains failed

The first combined run executed 108 methods: PR817's previous 105 plus PR816's
three additions. It completed in 260.525956 seconds with **107 passes and one
failure**, zero errors, skips, expected failures or unexpected successes. It
was not rerun or replaced.

The failing method was
`tests.test_core_seven_part04_capture.Part04CaptureTests.test_held_descendant_descriptors_are_killed_after_leader_exits`.
Its single immediate `/proc/<pid>/stat` read required `Z` and observed `R`.
The other 107 methods passed, including all three PR816 additions, all eleven
PR817 additions and the historical relocation replay method. All nine checked
source hashes matched before and after that run.

The failed assertion did not preserve the descendant PID, terminal receipt or
state sequence. Its temporary files were gone when the suite finished. The
exact timing of that individual kernel observation therefore remains
**unresolved**; it is not relabelled as a proven harmless event.

### Cleanup receipt scope

The production fields describe successful group signalling, the owned leader's
reap, captured stream drain and deadline observations. They do not record an
exit or reap observation for every descendant. A successful signal syscall is
not an all-process exit barrier; see the Linux man-pages project's
[kill(2) return-value contract](https://man7.org/linux/man-pages/man2/kill.2.html).

Linux exit processing allows separate EOF and zombie observations. In
[Linux v6.18, commit 7d0a66e4bb9081d75c82ec4957c50034cb0ea449,
kernel/exit.c](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/kernel/exit.c),
`do_exit` performs descriptor cleanup before calling `exit_notify`, which
publishes `EXIT_ZOMBIE` (retained references: lines 961, 978 and 749). This
ordering supports a possible observation window. It neither identifies the
exact running kernel build nor uniquely explains the failed sample.

### Minimal correction of the existing descendant method

The method additionally requires actual `drain_complete`, no
`cleanup_incomplete`, and no `cleanup_deadline_exceeded`. It observes the known
harmless Python descendant under the **same fixed `started + 1.5 seconds`
total test deadline**. Only a real `Z` state or confirmed path disappearance
before that deadline passes. Persistent live states and late terminal reads
fail. Every observed process-group identity must match the fixture group. PID,
state transitions and elapsed observations are printed.

The original collector-duration assertion and final zombie/disappearance
requirement remain. This finite fixture check is not a production proof about
an arbitrary process tree.

Only the corrected method was executed after the full attempt:

| Directed scenario | Observation | Outcome |
| --- | --- | --- |
| Actual child, no observation injection | Real disappearance at 0.070262 s | Method passed |
| Two explicitly injected `R` reads, then an actual read | Real disappearance at 0.067620 s | Method passed |
| Explicitly injected persistent `R` | Deadline reached at 1.500085 s | Method failed as required |
| Delayed return of an actual terminal observation | Real disappearance returned at 1.584551 s | Method failed as required |

These are four invocations of one existing method, including two expected
negative failures. They are not new CI test IDs or a second 108-method green
run. Injections occur after the genuine collector call. Each case retains its
actual receipt, raw files, PID/group, actual read contents, delivered states,
injection flags and times. PID values belong to the local execution namespace.

## Inventory and provenance

All original 709 isolated test IDs remain. PR816 adds three, bringing the
existing shards to 712. PR817's eleven controls keep their independent job and
remain disjoint; the workflow explicitly checks the 723-ID union. The capture
module remains 41 methods, Part04 runner 17 and relocation runner 23. No skip,
expected-failure allowance, timeout increase or test deletion was introduced.

All 33 PR816 relocation method bodies are unchanged. Among historical methods,
only the descendant observation method described above was corrected; the
other old bodies are unchanged. Inventory verification loads and compares
names without executing those test methods. Other workflow jobs, source
checks, solver pin, triggers and before/after head guards remain unchanged.

The source integration contains 52 paths before this report and package:
38 retain exact PR816 blobs, nine retain exact PR817 blobs, and five are
integration-owned: the initialization workflow, relocation fixture, timeout
control mode selection, the descendant capture method and diagnostic scope
documentation. PR816's other code and evidence were copied without alteration
or local execution of its native loader, machine mutation or compiler tests.

Production limits stay 60 seconds for the process, two seconds for cleanup and
50 ms for pending EIO; byte budgets are unchanged. The v2 receipt and both
readers retain their mandatory deadline field and existing v1 rejection. Old
v1 evidence still requires its original checker and is not upgraded here.

## Exact-parent CI and the next gate

The original PR heads were read back unchanged and open on the same baseline.
Final readback found PR817 **8/8 successful workflows** and PR816 **19/19
successful workflows**, all on attempt 1. These qualify their own commits,
not the integration commit.

PR817's [initialization workflow](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42551190986)
completed 80/80 jobs. Its
[independent deadline job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42551190986/job/128946935949)
ran eleven methods in 27.062 seconds. Its historical
[relocation runner B job](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42551190986/job/128946936509)
ran all ten assigned methods in 57.976 seconds, including the formerly failing
replay method. Both original logs and all 80 job records are retained.

The published integration head must run its own relevant CI before source
branch integration. The local 107/108 record and directed follow-up remain
separate even if subsequent CI succeeds.

## Evidence and limits

`review-evidence/hia-part04-fixture-integration-20261109-e5ee/` contains validation,
the member hash manifest and a compressed complete local evidence/CI-readback
package. It preserves the mechanical-union red, first full failure, all four
directed cases including expected negatives, inventory scripts/results, source
maps, independent review, source references and original PR817 job logs.
Inherited PR816 raw log whitespace remains unchanged; new source changes have
a clean focused whitespace check.

The original PR808 CI failure's unique cause remains UNKNOWN. This integration
does not establish a global Core/compiler/ABI/FFI/ISA/loader theorem, arbitrary
descendant containment, Agent adoption, stable NDU economic benefit, public
release selection or online deployment. Overall six-track acceptance is
separate.
