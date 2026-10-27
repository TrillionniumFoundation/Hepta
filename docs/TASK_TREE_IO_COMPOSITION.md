# Worker-owned I/O in a bounded task tree

This profile connects the existing consuming task tree, explicit shared task
reservation pool and caller-driven local-stream reactor on hosted
`x86_64-unknown-linux-gnu` Rust. A task worker can attach its **locally owned**
reactor to the same pool as its group. Tree cancellation wakes an actual
blocked `poll`; the worker collects or abandons requests, closes its reactor
and returns before its group can finish joining.

The reactor remains `!Send` and `!Sync`. A cancelling thread never reads,
writes, moves or closes the reactor's user endpoints or buffers. There is no
new task scheduler, `async`/`await`, TCP/TLS API, arbitrary file I/O, independent
I/O IR proof or whole-process memory bound. The independent C/LLVM/resource
and concurrent-IR profiles still reject this composition explicitly.

## Source interface

| Operation | Result and requirements |
| --- | --- |
| `group_io_configure(mut group, reactors, port_slots, request_slots, bytes)` | `bool`. Configure an existing explicit shared task pool once. The invoking group must have admitted no tasks and the pool must have no outstanding worker reservations. The four limits are `usize`; zero limits are valid refusals. At most 256 reactors are supported per pool. |
| `group_io_snapshot(read group)` | Copy `GroupIoReport`. Any remaining attached group can observe the pool, including after another tree in that pool has joined. An unattached group reports all-zero/unconfigured state. |
| `io_attach(mut reactor, read sender)` | `u8`. A worker's nonconstructible `Sender<u64>` authorizes a single attachment. The reactor must be successful, empty, unbound and not shut down. Its group must have an active worker and a configured I/O pool. |

All three operations conservatively require `{alloc,block,panic,io,write}` in
this source profile. Existing operations and owner obligations are unchanged:
`io_take`/`io_wait` consume a request and return its original buffer;
`io_shutdown` consumes a reactor. `group_cancel` does not discharge a join.
An attachment refusal leaves the original reactor owned by its caller, which
must still shut it down. A refused request keeps its original buffer in its
linear completion ticket.

Attachment status zero is success. Existing status 1 means an already
cancelled group, 5 means a native wake-socket setup error, and 12 means an
actual fallible metadata reservation failed. New status 15 rejects a missing
pool, invalid attachment authority/state, duplicate binding or nonempty
reactor. Status 16 means a shared pool limit refused attachment or buffer
admission. Status 17 means the group's bounded list of 64 live registrations
is full. Removing an attachment allows later reuse of that slot.

Examples are actual source programs:

- `examples/task_io/pipeline.hepta`: two workers in a four-node tree transfer
  and verify 256 bytes through independent local reactors; a surviving sponsor
  observes released task and I/O reservations after joining the tree.
- `examples/task_io/cancellation.hepta`: a child announces its admitted read,
  transfers into the parent, observes propagated cancellation and collects its
  original buffer before the whole tree joins.
- `examples/task_io/recovery.hepta`: reactor and byte-budget refusal, retained
  refused input, cancelled and timed-out reads, a real broken peer, then
  successful endpoint reuse and final zero reservations.

## What the shared pool actually counts

| Reservation | Admission | Release |
| --- | --- | --- |
| One attached reactor | Successful `io_attach` | Reactor shutdown/native drop after local operations/endpoints are cleared |
| Configured endpoint slots **plus two** wake endpoints | Successful attachment; full capacity is reserved, not only currently open user endpoints | Binding destruction closes both wake endpoints before returning its slot reservation |
| Configured request slots | Successful attachment | Binding destruction |
| Admitted buffer capacity | Immediately before request slot insertion; checked addition under the shared I/O budget mutex | Collection or shutdown/native drop removes that resident buffer |

Completed, cancelled, timed-out and errored-but-uncollected buffers continue
to consume capacity. The pool counts `Vec<u8>::capacity()`, including its
initialized but unused tail, rather than requested transfer length. Failed
shared-byte admission changes neither local occupied slots nor pool bytes.

`GroupIoReport` includes the four limits, current reactor/endpoint/request/byte
reservations, their peaks, attachment and byte refusals and one-shot wake
notifications. Existing `GroupBudgetReport` remains a separate report of the
same explicit pool's thread, input-length, queue and requested-stack
reservations. Each report is coherent under its own mutex; reading both is
not an atomic cross-report snapshot. Input length and reactor capacity are
separate conservative reservations, not a disjoint measurement of heap bytes.

The limits exclude buffers before admission and in refused tickets, ordinary
worker/foreign allocations, metadata and allocator overhead, native socket
buffers, actual OS stack rounding, RSS and CPU. Reactor metadata is allocated
before attachment and may retain enlarged capacity after a refused attach.
Initial group/`Arc` allocation failure and `panic=abort` can still terminate the
process. They are not disguised as recoverable budget errors.

Every recoverable attachment operation—registry/poll-array reservation, native
socketpair creation and nonblocking setup—completes before pool counters are
committed. Failure drops any newly created endpoints and leaves previous pool
reservations intact. Identity numbers may have gaps; they never wrap or confer
ownership of a reused native FD.

The one-time configuration can also occur through an unused surviving sponsor
after older groups in the pool have joined. It freezes the I/O limits from
that point onward; it is not a retrospective budget for prior work.

## Cancellation and lock order

The group holds only weak references to cancellation wake objects. A binding
owns a private Unix socketpair; the reactor polls its read endpoint alongside
pending user endpoints. Cancellation publishes the group's atomic flag and
closes the wake object's write endpoint. The resulting persistent EOF/HUP
wakes a blocked `poll`, including cancellation immediately before the actual
system call. There is no periodic polling timer or allocation per pump.

Registration and cancellation publication use the same group-state mutex.
Cancellation either makes attachment return status 1 or finds the fully
published wake object. Adoption retains each worker's original shared group;
the existing tree traversal reaches that group after transfer. Failure still
propagates to the root and then across siblings before joining.

The reactor checks the flag before each nonblocking attempt and after wakeup.
Pending requests become cancelled while preserving their transferred prefix
and initialized tail. A terminal result already completed by a pump is sticky.
If cancellation races with a nonblocking read/write already in progress, that
operation may have taken effect before the flag is observed. Cancellation
cannot undo bytes already transferred. Read-only status queries do not pump.

Notifications take `group state → wake writer → I/O budget`. Attachment takes
`group state → I/O budget`. Binding destruction takes only the I/O budget
after closing its sockets, and never takes topology/group-state locks. This
matters when a canceller releases the last temporarily upgraded `Arc` while
holding group state. Dead weak registry entries are pruned on later attach or
cancel; they own no sockets or buffers. No mutex is held across worker join.

All local I/O owners must be consumed before a source worker returns. The
worker's `u64` result cannot return an I/O owner, and `Sender` cannot be copied
or constructed in source. Joining therefore waits for admitted local I/O
cleanup as well as worker completion. Native Rust drop has the same cleanup
path as `io_shutdown`. Arbitrary native/FFI code remains outside these source
constraints; a noncooperative foreign blocking call is not interrupted.

## Qualification and retained failures

```sh
RUSTC=/absolute/path/to/rust-1.90.0/bin/rustc \
  python -m tools.qualify_task_io --repeats 3 --output /tmp/task-io-attempt.json
RUSTC=/absolute/path/to/rust-1.90.0/bin/rustc \
  python -m unittest tests.test_task_io tests.test_io_runtime \
    tests.test_task_trees tests.test_shared_runtime tests.test_task_groups \
    tests.test_group_timeouts
```

The qualifier retains an adjacent `.files` directory. The pure data validator
`validate_report(report, minimum_repeats=3)` needs those retained files and the
current source; it does not compile or execute anything. A success has
`status="passed"` and `ok=true`. An output path is created exclusively and an
earlier failed attempt cannot be overwritten.

Every repetition runs all three source binaries plus the exact production
runtime's native matrix: actual blocked and pre-poll cancellation, partial
read preservation, timeout/system-error recovery, completion-before-cancel,
native drop, four budget dimensions, two real allocator refusals, one injected
native socketpair refusal, failures setting each of the two actual wake
endpoints nonblocking, and registry-capacity recovery. Both endpoint-setup
failures check kernel descriptor closure, unchanged pool counters and a
successful retry. A rejected adoption
must cancel and join a child already waiting in the native poll path, reclaim
its resources and let a new group reuse the same pool for timeout recovery.
The matrix also executes 64
parent/child cancellation-failure races, 64 attachment-cancellation races, 64
readiness-cancellation races and 32 cross-group byte-admission races. Actual
registered buffer deallocations and kernel descriptor closure are checked.

A deterministic ownership interleaving holds group state and a temporary wake
`Arc` in the canceller while the worker shuts down its reactor. The worker must
return its resident bytes without waiting for that state lock. The canceller
then releases the last strong reference under the lock, and the remaining
reactor/endpoint/request reservations must reach zero before joining. This
checks the documented final-`Arc` destruction boundary directly.

Five separately compiled wrong runtimes must fail: losing the wake endpoint
hits an actual two-second timeout; ignoring the shared byte limit, omitting
reservation release and leaking the resident buffer fail distinct assertions;
adding a group-state lock to wake-binding destruction reaches the controlled
last-`Arc` boundary and hits an actual two-second timeout.
A separately compiled illegal mutable alias must be rejected by Rust with
`E0499` and must not produce an executed binary. Ten invalid source controls
exercise ownership, effects, authority and report construction.

The receipt uses closed schemas and exact types, fresh source/report/emitted
code replay, compiler byte identity, exact compile/link/execute commands,
retained binary/object hashes, full fixed case/trial denominators and raw
stdout/stderr bytes. It rejects booleans used as counts, changed capability
claims, metadata-only builds, unrelated resealed source and inconsistent
native summaries. Reports are checkpointed before inspecting success;
mid-run failures keep prior results and planned unstarted repetitions, and
later case rows still run. Timeouts preserve non-UTF8 partial streams.

Hashes bind the receipt to observed inputs and artifacts; they do not
authenticate an arbitrary third-party author who rewrites every claimed
execution. The allocator, Rust compiler/std, libc, Linux readiness/descriptor
semantics and qualified host remain trusted external components. These tests
do not prove deadlock freedom, all scheduling interleavings, hard real-time
cancellation, production compiler refinement or universal resource safety.
