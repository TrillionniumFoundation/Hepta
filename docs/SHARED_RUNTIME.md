# Selection and shared task reservations

The [task-tree I/O extension](TASK_TREE_IO_COMPOSITION.md) adds fixed reactor,
endpoint/wakeup and request-slot reservations plus admitted buffer capacity to
the same explicit pool. Its report and native qualification are separate from
the thread/input/queue/requested-stack report described below. Neither report
measures total process allocation or RSS.

This hosted Rust runtime profile adds two concrete facilities: receiving from
two bounded task-group channels, and a reservation pool shared by explicitly
attached groups. Each `TaskGroup` remains a local linear owner that must be
joined, or transferred into a parent through the separate
[consuming task-tree API](TASK_TREES.md). The pool alone is shared ownership of
accounting state; it does not create a parent/child lifetime or implicitly cancel
other groups. The shared-runtime qualifier does not qualify task-tree behavior;
`validate_task_tree.py` supplies that separate evidence.

## Receive from two groups

```hepta
group_select_receive(read left, read right, mut value, prefer_right, millis)
```

The arguments are two distinct `TaskGroup` owners, an existing mutable `u64`
output, a `bool` preference and a `u64` duration in milliseconds. Both groups
must have been sealed. As with ordinary `group_receive`, a missing seal is a
runtime precondition failure under `panic=abort`.

The result is `Result<u8, u8>`:

| Result | Meaning | Output and channels |
| --- | --- | --- |
| `Ok(1)` | One value was received from the left group | Output updated; exactly that value removed |
| `Ok(2)` | One value was received from the right group | Output updated; exactly that value removed |
| `Ok(0)` | Both channels are closed and drained | Output unchanged |
| `Err(1)` | Neither channel became ready before the checked deadline | Output unchanged; no value removed by this call |
| `Err(2)` | The monotonic clock cannot represent the requested deadline | Output and channels unchanged |
| `Err(3)` | Both arguments name the same group | Output and channels unchanged |
| `Err(4)` | A selector registration cannot reserve a slot | Output and channels unchanged; partial registration removed |

The preferred group is inspected first on every attempt. If only the other
group is ready, it can be selected immediately. The caller can toggle the
preference after a receive, as in
[`select_pipeline.hepta`](../examples/groups/select_pipeline.hepta). There is
no implicit scheduler fairness guarantee or atomic snapshot of both queues.
Both groups' existing FIFO order and backpressure are retained.

Each call owns one condition variable and pending flag, registered through
weak references with both groups. Registration precedes polling. A producer,
worker completion, cancellation or failure sets the pending flag while holding
the relevant group mutex. The selector clears the flag **before** polling and
does not hold the signal mutex while inspecting either group. A notification
that races with polling is therefore seen either in the queue state or in the
pending flag before waiting. All nested locking uses group state → signal;
there is no signal → group path.

The selector computes one `Instant` deadline. Spurious wakes and pending
notifications reuse it. A zero duration checks current availability and closed
state. Once registration succeeds, observed ready/closed state takes precedence
over timeout. The duration does not bound mutex acquisition, OS scheduling,
worker execution or later joins. There is no polling timer or busy-wait loop in
the production selector. The underlying Rust condition-variable contract also
requires predicate rechecks after spurious wakes; see
[`Condvar::wait_timeout`](https://doc.rust-lang.org/std/sync/struct.Condvar.html#method.wait_timeout).

At most **64** live select calls may register with one group. The Rust runtime
supports concurrent registered readers, although the current source language
keeps group handles local. A selector's destructor removes both registrations
on every normal success, timeout and refusal. Vector capacity can remain until
group destruction. Ordinary `Arc` allocation failure is still process-fatal;
`Err(4)` covers a full registration list or its fallible vector reservation.

## Share admission reservations

```hepta
group_budget_configure(mut root, threads, input_bytes, queue_slots,
                       requested_stack_bytes, worker_stack_request)
group_budget_share(mut another, read root)
group_budget_snapshot(read root)
```

`group_budget_configure` returns `bool`. It attaches a fresh pool to an empty,
unsealed, open group that has no pool. The five limits are `usize`. The group's
existing queue capacity must fit the shared queue-slot limit. The explicit
per-worker stack request must be between 64 KiB and 1 GiB, inclusive; this
bounded profile avoids absurd native stack requests. Zero admission limits are
valid and refuse every affected admission. The configuration cannot be changed
after success, even if no worker has started.

`group_budget_share` returns `bool`. The target must be empty, open, unsealed
and unattached. The sponsor must already have a pool. The target's full fixed
queue capacity is reserved before attaching it. Refusal leaves the target
unattached and preserves the existing pool reservations. A later group can use
any attached group as sponsor. The sponsor's own join does not invalidate the
remaining groups because they each retain the pool through `Arc`.

Both operations require explicit mutable access to the target. Native Rust
borrow checking rejects a mutable target that aliases its read-only sponsor.
Attaching or cancelling a group does not discharge its source-level join
obligation.

### What is counted

| Reservation | Acquisition | Release |
| --- | --- | --- |
| Fixed `u64` queue slots | Configuration or attachment | After that group has joined all workers |
| Thread/handle slot | Before native thread creation | Native spawn failure, or actual group join |
| Submitted input length | Before native thread creation | Native spawn failure, or actual group join |
| Requested stack bytes | Before native thread creation | Native spawn failure, or actual group join |

All four dimensions use the same pool mutex and checked arithmetic. A spawn
must satisfy both its original per-group limits and the pool limits. A refusal
consumes and drops the submitted `Buffer`, matching existing `group_spawn`
behavior. Completed workers conservatively keep their reservations until their
group actually joins them; completion alone cannot recycle a thread reservation.
Joining one group releases only that group's contribution.

The runtime reserves the join-handle vector slot before starting a native
thread. A fallible reservation error cannot leave a started worker with no
recorded handle. Native thread creation uses
`std::thread::Builder::stack_size(worker_stack_request)`. If native creation
fails, both group and pool admission changes roll back and the owned input is
dropped. Rejection and spawn-failure counters remain visible after recovery.
Rust documents that the actual stack may exceed a request because of platform
minimums in [`Builder::stack_size`](https://doc.rust-lang.org/std/thread/struct.Builder.html#method.stack_size).

`GroupBudgetReport` is an unconstructible, copyable runtime report. It contains
the limits, the worker stack request, current reservations, peaks, attached
group count, admission refusals, spawn failures and queue-attachment refusals.
An unattached group returns `attached=false` with zero fields. A snapshot is
coherent for one pool; source code can inspect it through any remaining attached
group. Reservation peaks include reservations subsequently rolled back after
native spawn failure.

The pool bounds **explicit reservations for attached groups**. Its input count
is submitted buffer length, not live heap usage. Its stack count is the requested
size, not actual OS mappings: platform minimums, rounding and guard pages can
change actual stack memory. Existing queue allocation occurs when `task_group`
is created, before a later pool attachment. Unattached groups, buffers allocated
before submission, worker/FFI allocations, metadata, RSS and CPU time are
excluded. There is no process-global allocator hook in production and no
global physical-memory claim.

## Executed qualification

```sh
python tools/validate_shared_runtime.py --repeats 3 \
  --output artifacts/shared-runtime.json
python -m unittest tests.test_shared_runtime tests.test_group_timeouts \
  tests.test_task_groups
```

The qualifier uses the pinned native Rust compiler, and native GCC on Linux
for one qualification-only `pthread_create` wrapper. It requires actual
execution; there is no fixture fallback. Per repetition it executes:

- A Hepta source pipeline with two producers, 128 messages per group, explicit
  alternating preference, exact sum 19,328 and no active worker after joins.
- A Hepta source shared-pool scenario with cross-group queue, thread, input and
  requested-stack reservation checks; a queue refusal, an admission refusal,
  release after joins and successful reuse.
- 128 registration/send races, 64 concurrent cross-group budget races, both
  ready-group priorities, closed-state and identity controls, two spurious-wake
  deadline cases, cooperative worker failure waking selection, and registration
  capacity/allocation refusals.
- Independent refusals at thread, input and requested-stack limits; an actual
  failed join-handle allocation and an actual `pthread_create` error. Both
  input payloads are observed deallocated exactly once, all admission state is
  rolled back, and subsequent native spawns succeed. Pool reservations are zero
  after the final joins in the native controls.

Reports retain source/compiler/runtime identities, native build and executable
identities, the linked injector object identity, raw output, exact case counts
and measured duration for every repetition. The report validator rejects
missing executions, metadata-only builds, changed case denominators and
unsupported safety claims. Hashes bind records to source; they are not
signatures or a general proof that arbitrary submitted records are truthful.

The separate native controls inspect private runtime state and inject native
allocation/thread failures. They complement the source programs. They are not a
formal proof of the Python compiler's lowering, a concurrent-language memory
model, asynchronous I/O, an arbitrary-arity `select`, a structured task tree, a
worker termination guarantee, or a whole-process resource budget.
