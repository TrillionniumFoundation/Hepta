# A complete HIA quota-accounting module

This application supplies one complete, bounded business module: accounting for
an agent worker's available and reserved compute units. Credit, reservation,
consumption, cancellation of a reservation, capacity checks and error selection
are written in `hepta/apps/quota_v1.hiaasm`. Version 2 adds an explicit debit of
available units in `quota_v2.hiaasm`. The host does not implement these balance
calculations. This module does not replace the worker, its authentication, its
process supervisor or the rest of hepta-runtime.

Both programs are independently verified HIA Core v6. Each transition has 63 VM
ticks in the registered programs, no allocation, no loops, no internal calls and
no external effects. The application admits at most 128 ticks, zero heap bytes
and one frame. The native mode calls the same verified programs through direct
LLVM and an actual Clang 20+ GNU/Linux driver. There is no Rust/C implementation
fallback. The interpreter is the explicitly selected default mode.

## Installation and complete use

Install the [fixed candidate](HIA_RELEASE_CANDIDATE.md), then run the commands in
separate processes. The ledger parent directory must exist.

```sh
python -m hepta.apps.quota --ledger /tmp/worker-quota init --initial 100
python -m hepta.apps.quota --ledger /tmp/worker-quota apply task-1 reserve 70
python -m hepta.apps.quota --ledger /tmp/worker-quota apply task-1-used consume 40
python -m hepta.apps.quota --ledger /tmp/worker-quota apply task-1-unused release 30
python -m hepta.apps.quota --ledger /tmp/worker-quota status
python -m hepta.apps.quota --ledger /tmp/worker-quota upgrade upgrade-1
python -m hepta.apps.quota --ledger /tmp/worker-quota apply task-2 debit 10
```

The resulting state is available=50, held=0 under version 2. Add
`--clang /path/to/clang-20` before the subcommand to select actual native
transitions. Native compilation failures are errors, never a request to switch
to the VM silently. Native artifacts are created in a private temporary
directory and their verified build identities are retained by `HIAEngine`.

Repeated submission of the exact same request ID and payload returns its
original committed result. Reusing an ID for different arguments rejects.
`apply task-3 reserve 10 --cancel` records a terminal cancellation without
changing balances; retrying task-3 does not revive it. Release of already
reserved units is the separate `release` HIA operation. The host serializes one
account, not individually owned reservation objects: authorization and mapping
worker tasks to reservations remain obligations of the caller.

## Exact interface

The C-compatible public entry is:

```c
uint64_t transition(uint32_t available, uint32_t held,
                    uint32_t amount, uint32_t operation);
```

All inputs are exact u32 values; Python bools, negative values, fractions and
values outside u32 reject before dispatch. The maximum aggregate capacity is
2^31−1. The result packs available into bits 0–30, held into bits 31–61, and a
status code into bits 62–63. The host only unpacks these fields.

| Operation | Code | HIA rule |
| --- | --- | --- |
| Credit | 0 | Increase available only when total plus amount fits capacity |
| Reserve | 1 | Transfer available units into held, requiring sufficient available |
| Consume | 2 | Deduct held units, requiring sufficient held |
| Release | 3 | Transfer held units back into available, requiring sufficient held |
| Debit | 4 | Version 2 only; deduct available, requiring sufficient available |

| Result code | Meaning | State |
| --- | --- | --- |
| 0 | Applied | Complete HIA transition result |
| 1 | Insufficient units | Unchanged |
| 2 | Unknown operation for this version | Unchanged |
| 3 | Invalid aggregate state, amount or capacity overflow | Unchanged for a valid incoming state; invalid incoming states return zero balances |

Invalid input state/amount takes precedence over unknown operation, followed by
funding and capacity checks. Amount zero is valid for a known operation. The
journal never admits an invalid state; direct ABI adversaries still exercise
that rejection result.

## Host ownership, cancellation and recovery

`hepta/apps/quota.py` is the trusted POSIX adapter. It owns file access, the
exclusive flock, immutable record publication, request identity and the program
registry. A thread lock serializes calls on one instance; reentrant callbacks
reject. The originating PID is checked before acquiring that thread lock, so a
forked child cannot use an inherited instance or its shared flock descriptor.
A second process or instance cannot acquire the same flock. This is a
cooperating single-owner protocol on a local filesystem, not a distributed lock.

Each event binds sequence, previous record hash, exact HIA program hash, old
state, request and result. Before any publication, the live backend result is
compared against an independent HIA VM replay of those same inputs; this includes
genesis and migration. A well-typed but incorrect backend result therefore
cannot be committed and poison future recovery. This extra check has a real
execution cost and is part of the qualified application, including native mode.
A fresh open and every mutation replay the whole
bounded history through the independent HIA interpreter. Unsupported fields,
duplicate JSON keys, noncanonical encodings, hash/sequence gaps, source mismatch
and results that disagree with replay reject. No damaged committed record is
deleted, rewritten or silently truncated. A hash chain is an integrity check;
it is not a signature and cannot detect an administrator restoring an entire
older directory without an independent external checkpoint.

The writer creates a private stage, writes and fsyncs it, creates the next record
with a no-replace hard link, and fsyncs the directory. An interrupted stage is
not a committed record. An exception during publication or its acknowledgment
is `CommitUnknown`; recovery retries the same request identity and reconciles
the retained record. An already published record is never reapplied. Tests
retain the same classification for a lost link acknowledgment, interruption
after publication and a failed post-commit readback. The CLI emits
`status="unknown"` and exit code 3 for this condition; ordinary request or
pre-publication errors use exit code 2.
The qualification also kills a real child process after link publication and before its directory-sync
acknowledgment, then recover in a fresh owner. This tests process death, not
physical power loss or every filesystem's crash guarantees.

The cancellation callback is observed before the bounded pure computation and
again immediately before record publication. A cancellation at either point
discards the computed state and records a terminal cancellation. Once record
publication begins, the commit must be reconciled; cancellation cannot retract
a committed operation. There are no external effects to compensate, and this
protocol does not claim exactly-once delivery of network, payment or process
effects.

The journal admits at most 1,024 committed records of 4,096 bytes each and a
bounded orphan-stage inventory. Replay is linear in retained history. Exhaustion
rejects new work; there is no automatic history compaction or deletion. The
caller must provision a new explicitly reconciled account if this bounded
example is extended to sustained service. Directory ancestors, filesystem,
Python runtime, compiler, native loader and hardware are trusted; hostile
same-account mutation is outside this application qualification.

## Upgrade contract

The only supported upgrade is v1 to v2. The old version, new version and both
program identities are retained in the upgrade record. Both versions use the
same fixed balance schema. The new HIA program performs a zero-credit transition
and must preserve the current state before publication. The next transaction
uses v2; old records continue to replay using their original v1 program.

A missing or changed historic program blocks reopening. Downgrade and unknown
versions reject. Repeating the original upgrade identity returns its recorded
result. This is a complete two-version application upgrade, not a generic
migration proof, live stack-frame replacement or arbitrary model-state upgrade.

## Reproducible qualification

```sh
python -m tools.qualify_hia_quota_application \
  --clang /path/to/clang-20 --output /tmp/quota-qualification-new.json
```

The fixed inventory includes an independent Python integer oracle with 1,768
boundary/random cases per version per backend, complete business sequences,
errors, cancellation before and after computation, repeated IDs, real process
death, lost link acknowledgments, directory-sync failure, corruption, missing
records, program identity changes, lock contention, thread serialization,
reentrancy, strict scalar types, budget exhaustion, CLI restarts and an actual
native v1/v2 upgrade followed by VM replay. Native compilation, VM execution and
native execution are separately recorded. The command fails on skips, incomplete
inventory, test failure or changing source. `--vm-only` explicitly narrows the
result; it never supplies a native execution pass.

This qualification does not measure an HIA speedup. The
[separate value protocol](HIA_INTELLIGENCE_CONTRACT.md) determines when a language
or NDU advantage can be claimed.
