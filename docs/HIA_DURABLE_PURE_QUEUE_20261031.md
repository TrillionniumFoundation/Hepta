# Bounded recovery for the existing pure native u64 owner

`hepta.hia_durable_queue.DurableOwnedQueue` adds a durable intent/commit boundary
to `OwnedAdaptiveRuntime`. It reuses that runtime's existing closed admission:
an exact `(u64, u64) -> u64` entry, total scalar operations, no effects, bounded
acyclic helper calls, and exclusive native u64-array state. It does not add an
alternative interpreter, compiler, native pointer format or proof importer.

The supported recovery event is termination of a Linux process using trusted
local storage. The caller supplies the same Core program, policy and expected
journal identity. A new owner is independently checked, proved, built, loaded
and checked against the saved exact native artifact, driver and compiler
digests. Changed source, Core, policy or native bindings refuse recovery before
queue replay. A journal does not authorize a foreign executable or grant a
previous serialized proof any authority.

## Durable execution order

| Durable state | Next action | Recovery behavior |
| --- | --- | --- |
| Last committed values and bounded request history | Persist one request ID, exact work digest and pending intent | The pending request retains the last committed input values. |
| Pending intent | Persist one execution-attempt credit charge | A crash after reservation consumes the credit, including zero progress. |
| Charged pending intent | Submit and execute the existing native queue | An interrupted process loses its private native array. Recovery starts from the durable input and repeats only this pure computation. |
| Complete native result | Persist output values, result and committed-step count; fsync the new file, replace the checkpoint, fsync the directory | Only after those operations does `execute` return a durable acknowledgment. |
| Committed request ID | Retry of the same ID and work | Return the saved result without another native call or credit charge. Reusing an ID for different work rejects. |

An exception after a potentially effective rename poisons the current wrapper.
The caller must close and recover; the live process cannot choose an assumed
older checkpoint and continue. The recovery reader uses only the committed
checkpoint. An interrupted temporary write is not a second source of truth.

There is one active writer. Descriptor-relative opens reject final symlinks;
the directory must belong to the effective user and exclude group/other access.
Lock and checkpoint files must also be private, ordinary, singly linked files.
The writer holds an exclusive nonblocking `flock` until close. An inherited
wrapper after `fork` is rejected **before** acquiring an inherited Python lock.
Child close drops only that process's storage descriptor references, leaving
the parent's lock effective; a fresh recovery still needs exclusive admission.

## Bounded history and restart accounting

The profile limits state to 4,096 u64 cells, each queue to 128 work items and
one billion total steps, and the encoded checkpoint to 8 MiB. A configured
lifetime permits at most 32 unique requests. It has independent finite caps on
execution attempts, owner starts and total admitted work. Every recovery
persists its owner-start charge before a fresh native build, including a build
that fails. Every native queue attempt is charged before submit/execute.
Restart never replenishes either counter. History is not compacted or silently
recredited; a full lifetime refuses further work.

Canonical JSON preflight bounds bytes, depth and decoded node count, rejects
duplicate keys, and verifies envelope, digest, exact fields, request identity,
result shape and accounting sums before a recovery build. The checksum detects
accidental corruption; it is not a signature or an adversarial anti-rollback
mechanism. The profile assumes the owner and its storage are trusted.

## API

```python
from hepta.hia_durable_queue import DurableOwnedQueue

with DurableOwnedQueue.create(program, journal_directory, fresh_build_directory,
                              [11, 17], clang=qualified_clang,
                              max_requests=32, max_attempts=64,
                              max_owner_starts=64) as queue:
    journal_id = queue.snapshot()["journal"]["journal_id"]
    result = queue.execute("request-001", [
        {"slot": 0, "delta": 7, "iterations": 5},
    ])

# After a process interruption, use a fresh build directory and the saved ID.
with DurableOwnedQueue.recover(program, journal_directory, another_build_directory,
                               journal_id=journal_id, clang=qualified_clang) as queue:
    result = queue.execute("request-001", [
        {"slot": 0, "delta": 7, "iterations": 5},
    ])  # either finish its pending pure intent or acknowledge its prior commit
```

`resume()` also executes the sole pending intent. The wrapper deliberately
exposes no mutable loan, foreign pointer, device operation, native-image
selection or external-effect interface that could invalidate pure replay.

## Concurrent conditional submissions

`execute(id, items, expected_committed_steps=revision)` adds optimistic
conditional admission for multiple producers sharing this one owner. Read
the revision from `snapshot()["journal"]["committed_steps"]`. Every request
contains at least one step, the counter is bounded and never reset, and the
retained history is append-only. The revision therefore cannot return to an
earlier value even if the numerical state values themselves return to an
earlier value. This is a version check for this pure queue, not a language-wide
concurrent memory model.

The existing mutex orders snapshot, precondition check, intent admission,
native execution and commit. A fresh request with a stale revision is rejected
before writing the journal, charging work or attempt credits, or entering
native code. For the same request ID and work, retry checks the revision of
that request's original input, derived from the validated committed prefix.
Thus a lost acknowledgment remains recoverable after another request commits.
The acknowledgment includes `input_committed_steps` and
`output_committed_steps`; these are derived values rather than a second durable
counter. A pending intent keeps its original input revision across recovery.
Omitting the keyword preserves the existing unconditional serialized API.

For a successful new request, publication of the committed checkpoint is the
state transition observed by subsequent operations; durable acknowledgment
still follows file and directory fsync. For a rejected stale request the
linearization point is the revision comparison under the mutex. A storage
failure leaves the live wrapper uncertain and requires recovery, so this
contract does not claim every interrupted call has a returned result.

External callers receive detached value snapshots. They receive no native
pointer capability and no right to mutate a borrowed array outside the mutex.
The declared device-permission set is empty: DMA, MMIO, IRQ, shared-memory
atomics and device recovery have no admission path in this profile. Physical
power failure and adversarial storage rollback remain outside the claim.

`tests.test_hia_durable_revision` runs actual Clang20 native owners with four
competing threads and with same-ID concurrent retries. It also exercises
historical acknowledgments after later commits and reopening, invalid/stale
preconditions without journal writes, and a failed native submission followed
by recovery. These finite executions substantiate the scoped contract; they
are not a formal proof of arbitrary schedules or external memory safety.

## Evidence and limits

`tests.test_hia_durable_queue` exercises real Clang20/Z3 native builds and fresh
process recovery. Fault subprocesses receive actual `SIGKILL` before launch,
after two native transition steps, and after commit-directory fsync but before
acknowledgment. The partial-prefix test records actual native progress and
values, then checks recovery against an independent arithmetic oracle. Other
cases cover lost acknowledgment, persistent attempt/start/request/step caps,
changed identities, malformed checkpoints, exclusive writers, a fork while
another thread holds the mutex, and injected rename/fsync failures. Run:

```sh
CLANG=/path/to/qualified/clang-20 python -m unittest tests.test_hia_durable_queue -v
```

These tests do not certify physical power loss, a particular disk controller,
network filesystems, arbitrary concurrent memory, DMA/MMIO/IRQ, external
transactional exactly-once delivery, or rollback-resistant storage. Replaying
the pure computation can repeat work, while retaining the same committed state
and one acknowledged request result. Historical native cost in a result is
not the entire journal/recovery cost, and interrupted work may have unrecorded
cost. No NDU economic advantage is inferred. `authority=DENY_ALL`,
`safety_certificate=false` and production qualification remain unchanged.
