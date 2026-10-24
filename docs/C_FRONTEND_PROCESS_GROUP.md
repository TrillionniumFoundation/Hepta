# Integration of the scalar frontend cleanup donor

This candidate is an isolated child of #24,
`2d35df6abe277dd0cefae13b031cdb9f8cbae611`. It incorporates the complete two-file
net diff from #23, rather than taking its test-only head commit:

- `9b07b286c99bb706daf5d88ceca8b61312c0b68b`: production cleanup implementation,
  parent #22 `ef20771b817c8b303efd3252e739868d7ecad1c9`.
- `07362d855ea94aacedd2aa50ac2bc39b0cfc6c9b`: regression test, parent 9b07b286.

`hepta/c_frontend.py` is byte-identical to the final donor implementation
(Git blob `898960c22a5a085a8e1e4f5a56d01460bbd45b28`). #24's C++ alias repair and
all other source are unchanged. The separate #25 comparator transport is not
imported: `tools/c2hepta.py` is a different subprocess path. No workflow changes.

## What the donor fixes

The bounded `_capture` previously killed only its direct process. If a driver
spawned a child inheriting stdout/stderr and then exited, the child could keep
the pipes open until the deadline and remain alive after the error was returned.
The donor recorded an actual failing orphan-process test before its repair.
That historical RED/GREEN evidence is preserved at
[PR #23](https://github.com/TrillionniumFoundation/Hepta/pull/23); it was not rerun
or relabeled as this candidate's qualification. No claim is made that the normal
pinned Clang helper itself creates such descendants.

The integrated implementation starts `_capture` subprocesses in their own POSIX
session/process group. Its `finally` sends SIGKILL to that isolated process group
even if the direct leader already exited, then waits for the direct child.
Cleanup occurs on normal completion as well as timeout, overflow and other
error paths. In the scalar frontend this wraps compiler version/resource/target
queries and the same-instance helper invocation; it is not a repository-wide
subprocess supervisor.

## Exact containment and test limits

The guarantee is limited to descendants still in the isolated POSIX process
group. Descendants that escape through setsid/setpgid are outside it. Non-POSIX
retains the previous direct-child-only fallback and has no equivalent group
cleanup qualification here. Waiting reaps the direct child; this code does not
claim to reap every orphan. This is not a malicious-process sandbox, a system
security-setting change, or proof of universal descendant termination.

The native regression creates only its own Python driver/child. It accepts the
recorded child being absent or a zombie after timeout, not a live resource user.
The donor's immediate `/proc` check is changed to a monotonic, two-second bounded
observation loop because signal delivery and process exit are asynchronous.
File disappearance is treated as exit; once exit is observed the test does not
send another cleanup signal. Its fallback cleanup targets only the recorded test
child. This is test robustness, not a newly reproduced production failure.
The original two-second capture timeout still assumes timely test-driver startup;
this is not a general startup-scheduling guarantee.

## Source-bound validation

The actual focused cleanup/protocol suite passed 9 tests on dot, including the
orphan timeout regression. An independent reviewer reran all 9 successfully and
verified donor production bytes and the bounded test adjustment. The existing
C++ regression suite and full candidate suite are separately reported with the
published exact head. No donor or previous #24 full-suite count is inherited.

No CI was queried, no merge/deployment was performed, no sandbox/process policy
was weakened, and no unrelated processes were intentionally signaled. Existing
local source and evidence are retained. Broader production, cross-platform,
process-tree isolation and whole-language qualification remain unclaimed.
