# Retain native child ownership until reap confirmation

The existing Linux x86-64 scalar differential observer now retains a failed
child cleanup as a process-local owner. This selectively incorporates the
cleanup mechanism from PR #335. It does not import that branch's separate
version dispatcher or loan-instrumentation runtime, and does not change the
existing in-process `ScalarMultiversionRuntime` or its generation leases.

## Failure being corrected

The observer already used `waitid(WNOWAIT)` so the direct child's PID remained
an identity anchor until process-group cleanup. It sent `SIGKILL` to that
original group and bounded the final `Popen.wait()` to two seconds.

If the final wait failed, however, the observer raised a generic rejection and
lost its explicit child owner. A reproduction with a real exited native child
and an injected wait-confirmation failure produced that generic exception with
no recoverable cleanup handle. The reproduction separately reaped the child;
it did not demonstrate a natural uninterruptible kernel wait.

## Current ownership and admission rule

- At most 32 observer calls may reserve a child slot at a time. Reservation
  precedes process creation; a failed spawn releases its reservation.
- Every spawned observer owns its original `Popen` object through cleanup.
  A confirmed integer exit status releases its slot exactly once.
- An unconfirmed reap raises `NativeChildCleanupPending`, retaining the owner
  in both that exception and a strong process-local quarantine. Discarding an
  exception cannot discard the pending owner.
- Any pending owner blocks admission of new observers. Already admitted calls
  still own their respective children within the same fixed 32-slot limit.
- `retry_pending_native_cleanup(timeout=...)` uses one total deadline in the
  range zero to two seconds across the retained owners. It retries only the
  original process wait. The group signal is attempted once; a retry never
  signals a numeric PGID that might have been reused after an interrupted wait.
- Temporary-stream close failures and an outer pinned-descriptor close failure
  cannot replace a pending-cleanup exception. Bounded secondary diagnostics are
  retained on its owner.

The sealed descriptor inherited by a child remains that child's own kernel
reference until it exits. This cleanup registry does not select, publish or
validate code generations. It retains OS process ownership, not a second Core
execution authority.

`native_child_cleanup_snapshot()` reports reservations, the fixed capacity and
per-owner cleanup states. Metadata locks do not wait behind an OS reap. During
concurrent cleanup this is a collection of bounded per-owner observations,
not an atomic snapshot of all process states.

## Recovery is not successful execution

A cleanup retry never invokes the entrypoint again or accepts the earlier
stdout as a successful observation. The original call remains failed even
when a later wait establishes that its child exited with code zero. Recorded
wait failures remain visible after recovery.

The registry is not durable across a host-process crash. It cannot force a
kernel task in uninterruptible sleep to finish, recover from arbitrary host
memory failure, or prove complete hostile-code isolation. The existing syscall
policy, artifact pinning, timeout, ABI, output and trap checks remain in force.

## Executed controls

`tests/test_hia_native_cleanup.py` uses a real Clang-built C transport DSO.
It distinguishes an actual native infinite-loop timeout and `SIGKILL` reap
from injected confirmation failures after an actual child exit. Controls cover
discarded exceptions, temporary-file and pinned-fd close errors, an error after
the child has already been reaped, failed spawn, repeated recovery and
nonblocking metadata/zero-timeout retry during another bounded wait.

The concurrency control temporarily lowers the same production admission
limit to two, starts two real observer children, and verifies that a third
attempt is refused before `Popen`. This tests the admission mechanism; it does
not claim a load test with 32 simultaneous native workers. All failure controls
retain an independent final original wait, so even a regression in the code
under test does not intentionally leave an unreaped child.
