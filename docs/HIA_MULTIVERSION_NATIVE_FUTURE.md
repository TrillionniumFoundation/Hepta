# Native in-process Future and cancellation component

This component owns the pending/cancelled/finished transition, cancellation token, callback ordering, actual futex synchronization and transferred callback/result lifetimes in HIA. The ELF executes in process. It is a private implementation component; the complete public BackgroundOptimizer and multiversion runtime are still being integrated. No whole-native claim follows from these component gates.

## Qualification

The unchanged original `_OptimizationFuture` and `PublicationCancellation` are the development oracle. Thirteen scenario pairs cover normal completion, cancellation, committed-token refusal, interrupted token/Future handoff, callback exceptions and abrupt interruption, recursive callback registration, a callback joining a completing worker, eight real waiters and a thousand retained callbacks. Eighty actual native cancel/complete races preserve the admitted outcomes.

A further 240 original/native real-thread rounds exercise cancellation versus token commitment, callback registration versus completion, and eight competing completion threads. The HIA owner preserves the original two condition acquisitions in `_complete`: a second normal completion between `done()` and `set_result()` produces the private InvalidStateError status, while concurrent cancellation is suppressed. The native race qualification actually exercises this branch. Existing terminal completions remain harmless.

Twenty lifetime and private-admission gates include actual signal interruption of a futex waiter, rejection of destruction with an active waiter or callback, PID rejection after fork, reentrant observations and destruction from callbacks, retention of a real weakly referenced closure until owner release, and exactly-once selected/losing result drops. The tests do not call `gc.collect`, change GC thresholds or use padding. Three actual malloc failures at allocation ordinals 1, 2 and 8 show that the failed incoming closure is dropped, the existing list is unchanged, the same owner can retry, and actual allocations equal frees after destruction. The allocator interposer exists only in the external qualification process.

Sixteen native packaging gates compare the HIA packer against the independent ELF construction, reassemble the readable mechanical source for an exact capsule check, exercise every header/length refusal, and check the original four-MiB policy limit. Production packaging uses the HIA packer and existing HIA general shared linker. The image and all report/source hashes are recorded in the companion JSON.

## Private ABI

`hia_mv_future` uses the six-word borrowed-buffer ABI. Source is exactly 64 bytes; output and owned workspace are at least 512 bytes and disjoint. The input is `HIAMVFQ1`, an operation and six u64 words. The last two words are zero. The workspace belongs to one process and one enclosing native strong owner.

| Operation | Meaning | Private arguments |
| --- | --- | --- |
| 0 | Initialize zero workspace | none |
| 1 | Cancel | none |
| 2 | Complete | result capability, result drop function |
| 3 | Settle an already cancelled token | none |
| 4 | Add a done callback | callback function, userdata, drop function, closure identity |
| 5 | Observe Future state | none |
| 6 | Wait for a result | timeout nanoseconds, infinite flag |
| 7 | Commit the private token | none |
| 8 | Cancel the private token | none |
| 9 | Observe token state | none |
| 10 | Destroy exclusively | none |

The reply starts with `HIAMVFR1`, status, value, Future state, token state, retained callback count, invoked callback count, caught callback exception count and creator PID. Future states are 0 pending, 1 cancelled and 2 finished. Token states are 0 open, 1 cancelled and 2 committed. Status is 0 success, 1 cancelled result, 2 timeout, 3 invalid private state, 4 abrupt callback, 5 allocation failure, 6 concurrent completion InvalidStateError, or 65 refusal. Invalid frame/extent returns `0xfffffffd` before acquiring or changing the owner.

The fixed mechanical bridge performs the HIA-selected raw syscall, CAS/exchange on the two actual mutex words, 64-byte node copying/allocation/free, or actual callback/drop invocation. It contains no Future transition decisions. Callback ABI is `u64 callback(owner_workspace, userdata)`: 0 normal, 1 caught Exception and 2 abrupt BaseException. Drop ABI is `u64 drop(userdata)` and is a nonthrowing trusted native capability release. These addresses and their strong lifetime come from the enclosing native value/closure owner, not untrusted public integers.

Callbacks and drops run after releasing the invoking thread's Future/token locks. Another thread may legally acquire a lock while a callback is running; concurrent qualification proves release using actual reentrant observation/result calls rather than requiring the global mutex word to remain zero. Pending callbacks stay strongly held after invocation, just as the original callback list does. An already completed Future invokes a newly supplied callback immediately and releases that incoming capability afterward. Abrupt callbacks stop that invocation sequence without replaying skipped callbacks. Destruction drops each retained node/value once, and rejects active calls before releasing anything.

## Remaining composition

The fixed private nanosecond wait protocol is not a claim that every public timeout object conversion has been implemented. Public value/exception carriers, wait/as-completed observers, and the full BackgroundOptimizer queue, ranking, accounting and shutdown interface still require integration. The coordinator must couple its selection linearization to this same token owner, without recursively acquiring the token mutex while it already holds it. Complete proof/build/capture/retirement composition remains separately qualified; this component accepts no caller proof or publication authority.
