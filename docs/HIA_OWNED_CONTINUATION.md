# Cancelled owned queues and verified version changes

`OwnedAdaptiveRuntime.continue_queue(token)` registers the unexecuted suffix of
one internally known cancelled queue. It requires a quiescent runtime, no live
loan, the same owner/allocation, the exact post-cancellation revision and values,
and a known incomplete native prefix. A completed, failed, stale, already claimed
or unknown queue cannot be continued. The existing one-pending-queue and
32-retained-queue bounds remain in force.

The original queue stays terminal. It records `continued_by`; the new queue
records the parent/root identities, committed prefix and remaining steps.
`queue_status` returns a detached observation, not an execution capability.
Cancelling a continuation and continuing again preserves the root prefix sum.
An already proved version may be selected at the quiescent boundary before the
remaining work executes. Only the suffix runs against the same live owner.

## Exception and cost contract

Registration rolls back both queue links and the bounded event history if event
recording fails before publication completes. A successful publication remains
discoverable through the parent if returning to the caller is interrupted.

Queue activation, lock exit, the first execution timestamp and the native call
share one exception-protected scope. Failure before native work restores the
submitted queue, activity, events and preparation-cost debt. Once native work has
occurred, progress and costs are irrevocable: a failed finish diagnostic is
retained and rethrown only after bookkeeping and cumulative-cost settlement.
If complete progress or cost accounting is unavailable, the runtime marks itself
poisoned, marks accounting incomplete, refuses further execution and keeps close
available to release the owner. Unknown costs cannot qualify a benefit claim.

`tools/qualify_hia_continuation.py` executes a real native prefix, actual verified
version change and exact suffix. The two control positions are 6/40 (inside the
first work item) and 22/40 (17 updates in the first item and 5 in the second).
Independent arithmetic checks the prefix and final states; original replay and
duplicate continuation are rejected, and final allocation/free counts balance.
The cancellation trigger is injected at a known native-call boundary; the
prefix and suffix arithmetic themselves are real native execution.

## Scope

This is a live-process, exclusive `u64` owner contract. Native transition
functions remain independently verified total scalar functions with no resource
or external effects. It provides no general heap/stack migration, persistent
crash recovery, or exactly-once external I/O. It does not by itself establish
positive optimization economics. The registered round-4 cost replication
retains the same three round-3 queues and records its new outcome independently.
