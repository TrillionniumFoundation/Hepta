# Part04 deadline observations and relocation timeout controls

## Original failure and qualification boundary

The starting source is `ffa64c93dd4c51190fda8c0f647481a31ffbcf07`.
[Initialization workflow 42529899242](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42529899242)
completed 78 of its 79 jobs successfully. In
[job 128881557778](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42529899242/job/128881557778),
the `target_timeout` subcase of
`Part04RunnerTests.test_complete_failure_replay_and_spawn_semantics` returned
`validated_markers=False`, where the fixture expected `True`.

The original CI log does not retain that subcase's terminal capture record.
Its unique historical cause therefore remains **UNKNOWN**. The controls below
establish concrete defects and repairs; they do not retroactively reconstruct
the original CI scheduler or replace the failed run with a retry.

The name `validated_markers` is an existing diagnostic replay flag. It means a
compatible capture is cleanly replayable, including a timeout with an empty
observed prefix. It is not a claim that all eleven markers were observed, and
neither value grants proof or target-module admission.

## Two independently demonstrated problems

### Test clock compressed cleanup as well as process time

The relocation timeout fixture accelerated the entire collector clock by 100.
This changed the production two-second cleanup interval into about 20 ms of
wall time. The replacement accelerates only the simulated process interval;
once it reaches 60 seconds, the clock proceeds at the real monotonic rate.
No production deadline, byte budget, ordinary assertion or historical test ID
is relaxed.

All controls used actual Python child processes, PTYs, signals and retained
capture files. They did not launch Lean or fabricate successful reads.

| Controlled observation on original source | Result |
| --- | --- |
| Delay the child's first output by 0.7 seconds | Replay succeeds with zero observed markers. This does **not** reproduce the CI failure. |
| Pause for 40 ms immediately after real `killpg` | Replay still succeeds. This also does **not** reproduce the CI failure. |
| After real `killpg`, pause for 40 ms and return one transient `EAGAIN` for the genuine stderr EOF | Eleven markers remain retained, but drain is incomplete and replay is false. This reproduces the failing assertion class. |
| Repeat the last control using the repaired clock and collector | Eleven markers remain retained; drain and replay complete within the unchanged cleanup budget. |
| Pause the same cleanup read for 2.1 real seconds | Cleanup remains failed; the repaired fixture does not extend the two-second limit. |

The first repair draft made a normal process timeout take the infrastructure
exception path and disabled normal draining. Its failing control is retained.
The final implementation routes a normal selector timeout back through the
existing process-timeout transition. A `waitid` result of `None` is not an exit
observation; cleanup deadlines still apply to it. Late actual reads or exits
remain ineligible.

### Part04 could accept cleanup observed after its deadline

The separate Part04 collector lacked the terminal observation checks already
present in the earlier diagnostic collector. A controlled real child exited,
its streams closed, and `wait` actually reaped it. Advancing only the wait
completion observation past the fixture's fixed cleanup deadline still yielded
`diagnostic_completed` on the original source. The repaired collector retains
`leader_reaped=True` and `drain_complete=True` but records
`cleanup_deadline_exceeded=True`, `cleanup_incomplete=True` and
`diagnostic_infrastructure_failed`.

The implementation now checks waitid, read, selector and wait return times.
Read bytes still consume the raw budget when they are observed too late to
persist. Once cleanup starts, exceptions do not create another cleanup window.
The production limits remain **60 seconds for the process, two seconds for
cleanup and 50 ms for pending EIO**. These are observation and admission limits,
not an assertion that OS scheduling or filesystem operations have a universal
wall-time upper bound.

## Version and independent replay

The new process trace is `p04-markers-v2`. The marker text grammar retains its
existing version and byte offsets. The additional mandatory boolean
`cleanup_deadline_exceeded` is bound into start/terminal records and the final
process summary. Both Part04 consumers verify its type, relation to cleanup
completeness, initial value and the exact terminal-to-result correspondence.
A rehashed late record cannot regain clean replay by changing one balancing
flag or calling itself completed.

Original `p04-markers-v1` evidence remains intact and may be inspected using its
original source/checker under its original semantics. The v2 checker explicitly
rejects v1 as new strict-deadline qualification. No historical record is edited
or promoted. This receipt consistency work does not authenticate a malicious
controller or establish a general compiler, ISA, ABI or hardware theorem.

## Tests and evidence

The new CI job registers eleven explicit controls, separate from the unchanged
historical inventories: 41 capture tests, 17 Part04 runner tests, 22 relocation
runner tests and the existing 709-control split. The eight direct collector and
two-consumer controls passed; all three complete relocation timeout controls
also passed. Their raw results and all controlled failures are retained.

The complete affected regression then passed **105/105 methods in 221.835
seconds**, with no skips, expected failures, errors or failures. This includes
the original 94 methods across the three affected capture/runner modules and
the eleven new methods; the earlier 8/8 and 3/3 checks are overlapping controls,
not additional unique tests.

The complete affected-suite result and source hashes are recorded in
`review-evidence/hia-part04-deadline-20261108-e5ee/validation.json`.
The evidence directory preserves the original GitHub failure, the controls
that did not reproduce it, both demonstrated red cases, intermediate failures,
successful repairs and the complete final regression log. Fresh CI on the
published commit is a separate required gate.
