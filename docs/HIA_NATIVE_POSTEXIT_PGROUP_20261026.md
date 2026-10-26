# HIA P2/P7 — refuse native subprocess descendants after worker exit (2026-10-26)

## Root cause
The previous source-native differential used an isolated Python child and
bounded file-backed stdout/stderr. A C shared object may fork and have its
direct worker return a valid JSON scalar before the forked descendant exits.
Waiting for the worker and reading a regular TemporaryFile **does not wait**
for the inherited descriptors or control the descendant. A native observation
could be marked as a match while in-group native code continued to run.

The #222 candidate cleaned process groups **on timeout**, but not on normal
worker exit. The #221 integration contained pinned memfd, typed scalar and
kernel RLIMIT controls yet still had a subprocess.run path. This change
combines the stronger source identity/policy with process-group handling and
closes the additional **normal-exit descendant** hole.

## Code
`hepta.hia_native_differential._observe_native` uses
`subprocess.Popen(..., start_new_session=True, pass_fds=(sealed_fd,))`.
On timeout or exceptional interruption it sends SIGKILL to the worker group
and reaps the direct child. **After every normal worker exit**, it attempts
a group-wide SIGKILL. ESRCH means the group is gone and normal output checks
proceed. If the group still exists, the evaluator kills it and rejects the
observation even if the direct worker returned a correct scalar or trap.

Output size, AS/CPU/file limits, exact Core ABI arity, sealed in-memory
executable identity and source resource-budget replay are unchanged.
Unknown/permission-failed group cleanup rejects.

This **does not** sandbox arbitrary native code. A malicious process may call
setsid/setpgid, escape the evaluator's process group, modify the host's state,
or use a broader kernel attack. A true hostile-DSO boundary requires separate
user/pid/mount namespaces, seccomp, cgroups and a privileged policy runner.
Never promote the present child runner to a hostile-code isolation guarantee.

## Real independent Linux control (not exact repo qualification)

A local Clang-compiled shared object forked, returned 7, and then wrote a
marker after a delay. Under the old wait-only policy the marker appeared.
After checking/killing the residual worker group on exit, the control
detected the surviving group and prevented the marker. These are real host
fork/kill semantics, not HIA compiler-output results.

## Committed acceptance

```sh
python -m unittest tests.test_hia_native_postexit_group -v
python -m unittest tests.test_hia_native_child_limits \
    tests.test_hia_native_pinning tests.test_hia_native_differential \
    tests.test_hia_v6_differential -v
```

The first suite compiles native C functions, verifies ordinary result/abort,
rejects successful parent + lingering fork, and checks group cleanup on
timeout. Complete checked-source Rust/HIA/LLVM differential and exact-head
suite remain unexecuted in this limited environment.
`whole_project_blockers_closed=false`.
