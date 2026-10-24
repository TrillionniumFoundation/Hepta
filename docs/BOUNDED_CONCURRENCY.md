# Bounded hosted task groups

This profile adds real native threads, a bounded group-owned `u64` channel,
cooperative cancellation, explicit worker failure, and numeric admission budgets.
It is implemented in `hepta/runtime_concurrency.py`; the frontend enforces
ownership and capability restrictions, and rustc validates the emitted program.
The existing `spawn` / `Task<u64>` API remains available.

## The budget being enforced

```hepta
let mut group = task_group(8, 32768, 4);
```

These three numbers mean:

| Argument | Runtime guarantee for this one group |
| --- | --- |
| `8` | At most eight workers are admitted during the entire group lifetime. Finished slots are not reused. |
| `32768` | The sum of the lengths of all admitted input `Buffer<u8>` values is at most 32,768 bytes. |
| `4` | At most four `u64` values are queued. The runtime allocates a fixed ring and does not grow it on send. |

Admission checks use checked addition under the group's mutex. A rejected
`group_spawn` returns `false`, increments the rejection counter, and releases
the transferred input buffer. **The input is consumed on both success and
rejection.** This makes the ownership rule independent of the result branch.

The task and input-byte limits may be zero. Queue capacity must be positive:
literal zero is rejected by the checker; dynamic zero fails a runtime guard.
Limits may be runtime values. `hepta check` reports them under
`resource_contracts`, with `scope=one_runtime_instance` and
`enforcement=runtime_admission_and_fixed_queue`.

These are **per-group admission and queue-storage limits**. They do not bound
other group instances, memory allocated before submission, allocations made
inside a worker, thread stacks, runtime metadata, allocator rounding, process
RSS, execution time, or cancellation latency. They are not a proof of a
whole-function or process-wide budget. Unsupported global claims such as
`resources { max_tasks=8; }` continue to fail closed.

## Ownership and worker capability

`TaskGroup` is a local linear resource. Every normal path must consume it through
one of the join operations. It cannot be returned, passed to a user function,
hidden in an aggregate, copied, or silently dropped. Moving a group to another
local binding is allowed and transfers the join obligation.

A group worker has exactly this nongeneric signature:

```hepta
fn producer(data: take Buffer<u8>, token: read Cancellation,
            output: read Sender<u64>) -> u64
effects { alloc, block, panic, write } {
    let count = len(data);
    let mut running = true;
    let mut i: usize = 0;
    while i < count && running {
        running = group_send(read output, 1);
        i = wrapping_add(i, 1);
    }
    release(move data);
    return count as u64;
}
```

`Sender<u64>` is an unconstructible, borrowed capability supplied by the runtime.
It cannot be owned, stored, returned, converted to a raw pointer, or copied into
a local value. Helper functions may receive it through `read` parameters.
The worker can poll `Cancellation` or observe `group_send` returning `false`.

As with the original task profile, a worker's complete transitive effects cannot
contain `spawn`, `unsafe`, or `ffi`. This check includes helpers and declarations
that understate their actual effects. The restrictions prevent nested task
creation and unchecked foreign operations in this profile; they do not prove
that an arbitrary worker terminates.

## API

| Operation | Result and behavior |
| --- | --- |
| `task_group(tasks, bytes, slots)` | Creates the local group and its fixed channel storage. Returns `TaskGroup`. |
| `group_spawn(mut group, producer, move data)` | Attempts admission and launches a real OS thread. Returns `bool`; input is consumed in either case. |
| `group_send(read output, value)` | Blocks while the ring is full. Returns `false` after group cancellation or failure closes the channel. |
| `group_seal(mut group)` | Ends admission. Existing workers continue. Calling it again is harmless. |
| `group_receive(read group, mut value)` | Requires a sealed group. Blocks for a value, returning `true` after updating the `u64` destination. Returns `false` when the channel is closed and drained, leaving the destination unchanged. |
| `group_join(move group)` | Requires a drained channel, joins every admitted worker, and returns `GroupReport`. An undrained channel fails a guard rather than blocking its own producers indefinitely. |
| `group_drain_and_join(move group)` | Seals, explicitly discards remaining messages while draining, joins every admitted worker, and returns `GroupReport`. |
| `group_cancel_and_join(move group)` | Requests cancellation, closes the channel, discards queued messages, wakes blocked channel operations, joins every admitted worker, and returns `GroupReport`. |
| `group_snapshot(read group)` | Returns an observational `GroupReport` snapshot without joining. Its `joined` field is false. |
| `group_fail(read output, code)` | Reports a nonzero application error. The first error wins; closes the channel and requests cancellation of siblings. |

Normal consumption follows this sequence:

```hepta
let mut group = task_group(2, 2048, 8);
assert(group_spawn(mut group, producer, move buffer(1024)));
assert(group_spawn(mut group, producer, move buffer(1024)));
group_seal(mut group);
let mut value: u64 = 0;
let mut total: u64 = 0;
while group_receive(read group, mut value) {
    total = wrapping_add(total, value);
}
let report = group_join(move group);
assert(report.joined);
assert(report.active_tasks == 0);
```

Use `group_drain_and_join` when output messages are intentionally discarded.
Use `group_cancel_and_join` when stopping before normal channel completion.
Neither operation forcibly terminates a worker that ignores cancellation or is
stuck in unrelated computation.

The effect upper bounds are conservative. Group creation and snapshot operations
declare `alloc, block, panic`; channel mutation and joins also declare `write`;
admission adds `spawn`. The implementation uses safe Rust synchronization but
does not advertise target-independent zero-allocation synchronization effects.
Groups are hosted-only and are rejected by the `no_std` profile.

## Reports and failure semantics

`GroupReport` contains admitted/rejected/completed/active task counts, admitted
input bytes, queue capacity and occupancy, high-water occupancy, send waits,
waiting senders, received and discarded message counts, the three configured
limits, a wrapping sum of worker return values, failure code, cancellation state,
and `joined`. It is a normal copyable snapshot, not a cryptographic attestation.
Unbounded observational counters saturate at the target `usize` maximum.

`group_fail` is an explicit cooperative application-error path. A worker still
has to release its input and return; siblings have to cooperate. When a joined
report is returned, the runtime has actually joined all successfully admitted
threads. A report does not promise that cancellation happened within a deadline.

The compiler still uses **`panic=abort`**. A worker panic remains process-fatal;
this implementation does not claim to contain panics, stack overflows, process
termination, or arbitrary hardware failures. Native tests deliberately verify
that a worker panic produces process failure rather than a successful report.
OS thread-creation errors are handled through `thread::Builder::spawn`: admission
accounting is rolled back, the transferred input is released, and
`spawn_failures` and `rejected_tasks` are incremented. The checked-in workload
evidence does not claim that an actual OS thread-creation failure was injected.

There is no general deadlock-freedom or termination proof. The runtime does
specifically prevent an unsealed receive and an undrained normal join from
masquerading as successful operation: these have explicit runtime guards.

## Executed evidence

With the pinned Rust compiler available through `RUSTC`:

```bash
python -m unittest tests.test_task_groups -v
python tools/validate_groups.py --repeats 3 --output evidence/groups/native_validation.json
```

The native validation builds and executes these checked-in sources:

- `examples/groups/bounded_pipeline.hepta`: eight workers, 32,768 delivered
  messages, four queue slots, observed blocked senders, and complete joins.
- `examples/groups/admission_budgets.hepta`: independent task-count, input-byte,
  and zero-task admission cases, including rejection and consumed inputs.
- `examples/groups/cancellation.hepta`: cancellation while producers are blocked
  on a full queue; all four workers finish with zero active tasks or waiters.
- `examples/groups/worker_failure.hepta`: nonzero application failure closes the
  queue, requests sibling cancellation, and joins all four admitted workers.

The JSON pins source, compiler, generated Rust, native artifact, and toolchain
identities, and includes actual exit codes and per-run counters. Timings are
observations for these small programs on this host. They do not establish a
latency bound or performance superiority over tuned Rust.

## Implementation references

- [Rust condition variables](https://doc.rust-lang.org/std/sync/struct.Condvar.html):
  queue predicates are checked while holding the same mutex and rechecked after
  wakeups, including spurious wakeups.
- [Rust thread builder](https://doc.rust-lang.org/std/thread/struct.Builder.html):
  launching returns an I/O result, allowing admission rollback on launch error.
- [Rust join handles](https://doc.rust-lang.org/std/thread/struct.JoinHandle.html):
  the runtime retains each unique handle until an explicit join.
