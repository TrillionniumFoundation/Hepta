# Rust shadow transport: owned process-group cleanup

The static `crosscheck_rust_shadow` and bound-execution
`crosscheck_rust_execution` protocols use the same bounded pipe transport.
Both retain their existing exact executable-byte pin, Core/request hashes,
output limits, report validation and non-authority claims.

## Fixed failure

The old transport called `Popen.poll()` during cleanup and killed the process
group only if the leader was still running. An exited leader could leave a
child holding stdout open: the deadline correctly rejected the run, but
`poll()` reaped the leader and skipped the still-running child. A leader
that closed the pipes and returned successfully, returned a nonzero status,
or emitted stderr had the same surviving-descendant problem.

The transport now keeps the original leader PID reserved with Linux
`waitid(WEXITED | WNOWAIT | WNOHANG)`. Pipe EOF is followed by non-reaping
exit observation within the original deadline. Every exit path then:

1. Confirms that the leader is still the runner's running or unreaped child.
2. Sends `SIGKILL` to its private process group exactly once, including
   when the leader has already exited successfully.
3. Reaps the leader with a bounded two-second wait and closes its pipes.

No `poll()` or `wait()` consumes the leader before the group signal. There
is no signal retry after a wait: an error reported after reaping must never
cause a signal to a reused numeric PID/PGID. Signal errors and unconfirmed
reaps reject; they cannot produce a successful comparison report. The
existing execution deadline does not include the bounded cleanup wait.

The runner refuses before spawning if Linux `waitid(WNOWAIT)` is missing
or unavailable, or if the process has a non-default `SIGCHLD` disposition.
Callers must not independently reap the runner's private child. If the
leader is unexpectedly no longer waitable, cleanup rejects without sending
a signal using an unowned numeric group identity.

## Scope

Ownership covers the fresh process group created by `start_new_session`
and descendants that remain in that group. A group signal terminates those
ordinary descendants; their new parent performs their eventual OS reap.
The transport is still a development comparison for a trusted, hash-pinned
binary. It does not provide hostile-binary containment, prevent deliberate
session/group escape, or preempt uninterruptible kernel waits. This fix
does not change Rust's production-authority status or close general
asynchronous cancellation and external-lifetime blockers.

## Executable regression

```sh
python -m unittest tests.test_hia_rust_transport_lifecycle \
  tests.test_hia_rust_crosscheck tests.test_hia_rust_execution_crosscheck \
  tests.test_hia_rust_crosscheck_cli -v
```

The new lifecycle tests use real forked descendants for successful,
nonzero, stderr, inherited-pipe deadline, running-leader deadline,
closed-pipe deadline and oversized-output cases. A separate test observer
is a Linux child subreaper, so it can verify actual `SIGKILL` exit status
and reap each descendant without altering the test runner's child policy.
The tests also observe the real leader with `WNOWAIT` at the exact group
signal, assert one signal per launch, and verify the leader has been
reaped after the call. Failures injected after an actual signal or reap
check that uncertain cleanup rejects and never signals again. Missing-capability
checks verify rejection before any launch. The other three suites build
and run the actual Rust producer and preserve both protocol contracts.
