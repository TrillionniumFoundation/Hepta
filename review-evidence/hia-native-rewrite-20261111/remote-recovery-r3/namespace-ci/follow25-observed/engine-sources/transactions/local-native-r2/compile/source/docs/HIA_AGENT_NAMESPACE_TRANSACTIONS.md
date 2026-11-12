# Native namespace transaction owner: reconstructed revision 3

This is a new reconstruction after the earlier cloud instance was lost. No
unavailable transaction revision 2 source or raw test is reused. The immutable
rows revision 2 and values revision 2 remain unchanged. This owner surrounds
all 31 row operations; it does not implement another reduced store or replace
the existing HIA request-journal decision kernel.

The transaction owner decides whether a call needs a writer lock, an immutable
committed snapshot, a pending view, a durable publication, or a rollback. The
fixed physical/value/row peers still have to be composed and validated. Until
that composition and migration pass the full caller gates, this component is
development code with no public selector and no SQLite fallback or retirement.

## Exact private protocol

The entry uses RWW: input 160 bytes, output at least 256 bytes, workspace at least
512 bytes. A new workspace is zeroed. Frames have 20 little-endian u64 words:

    [HIANTX03, command, sessionLo, sessionHi, call, actionSequence,
     action, status, a, b, c, d, e, f, g, h, 0, 0, 0, 0]

The session pair is not both zero. Commands are OPEN 1, BEGIN_IMMEDIATE 2,
EXECUTE 3, COMMIT 4, ROLLBACK 5, CLOSE 6, and ACK 7. New calls use exactly the
previous call plus one, with actionSequence/action/status all zero. OPEN carries
the actual admitted namespace-root lease in `a`. EXECUTE carries the complete
catalog operation in `a` and actual bind-vector lease in `b`. Other call data is
zero. The first call is OPEN with call 1. A closed connection accepts repeated
CLOSE and rejects other ordinary commands with the retained closed-connection
diagnostic category. A new OPEN on a used workspace is a framing refusal.

An ACK echoes the exact session, current call, issued actionSequence and action.
Exactly one action is outstanding. Status 0 means the actual issued peer
completed; 1 carries a known semantic/storage failure; 2 means the attempted
operation has no trustworthy completion observation. Status 2 permanently
refuses the transaction object. No ACK field, opaque handle, hash or boolean
authenticates arbitrary external data. The fixed executor must bind every
argument and response to the actual native peer, buffers, descriptors and
issued lease generation from that call.

Source snapshot r1 was retained before a private-workspace corruption probe:
changing a pending sync-data continuation from phase 71 to phase 111 allowed
its unchanged action-7 ACK to enter retirement. Source snapshot r2 adds the
exact 14-phase/action mapping and coherent pending/steady-state checks before
accepting any frame. The probe is an internal state-integrity control, not a
claim that ordinary callers can supply a transaction workspace. No committed
output from r1 is reclassified, and no absent native result is inferred.

Every action sequence is distinct within the connection. Every row execution
uses the public call as its row-action generation, including consecutive
autocommit reads that do not change durable transaction identity. Exhausted
transport counters refuse the session; opening a fresh session is independent
of the unbounded durable namespace history and never replays an uncertain call.

Output has 32 words: magic, status, session pair, call, action sequence, public
command, row operation, pending action, six action arguments, result lease,
changes, matches, error code, error detail, mode, transaction generation, view,
pending view, lifecycle, commit stage, first framing reason, continuation phase,
namespace lease, writer-lock lease, prepared-commit lease, zero. Status 0 is a
completed call, 1 an issued action, 2 a completed ordinary error, and 0xfffffffd
a permanent protocol/uncertain-completion refusal. An undersized workspace must
be discarded by the executor because it cannot reliably record poison.

## Native peers and physical completion boundaries

All peer semantics below belong to fixed native HIA owners. The mechanical
executor may perform the issued filesystem/descriptor operations and return
their exact observations; it must not choose rows, commit state or recovery.

| Action | Arguments | Exact successful result |
| --- | --- | --- |
| 1 namespace open | admitted root lease | owned namespace lease |
| 2 writer lock | namespace, original 10,000,000,000 ns wait | actual lock lease |
| 3 committed snapshot | namespace, writer lock or 0, current call | immutable view lease and head lease |
| 4 pending view | view, writer lock, current call | pending view lease |
| 5 rows | operation, bind lease, effective view, row generation, base view, pending view | independently owned result, changes, matches |
| 6 prepare commit | pending view, base view, writer lock, transaction generation | prepared immutable commit lease |
| 7 sync data | prepared commit | zero, after data and segment-directory durability |
| 8 publish head | prepared commit, base view, writer lock | actual published head lease |
| 9 sync root | published head, namespace | zero, after the parent-directory durability operation |
| 10 retire scope | scope, view, pending, prepared, kept result, generation | zero, only after all specified native leases are retired |
| 11 unlock | actual writer lock | zero |
| 12 namespace close | namespace | zero |
| 13 discard pending | pending, view, writer lock, transaction generation | zero, after uncommitted work is discarded |

Retirement scope 1 removes only an uncommitted prepared object after a known
retryable COMMIT failure; it retains the transaction view, pending writes and
lock. Scope 2 retires an autocommit read snapshot. Scope 3 retires a whole
transaction's pending, value, cursor, prepared and snapshot leases. A committed
segment or current head is never deleted by scope retirement. A separately
owned published result may survive the scope. The next call must not free a
result already transferred to its caller.

Success shapes are exact: every unused result word is zero. A known failure
carries a nonzero SQLite extended result code and detail in `a,b`, all other
words zero except a completed row error may carry its independently owned error
result in `c`. Known publication failure is permitted only if the actual atomic
publication did not occur. Missing completion or uncertainty is status 2,
never a guessed status 1.

## Complete transaction behavior

Autocommit SELECT acquires a fresh immutable committed snapshot without an
exclusive writer lock. It releases that snapshot after the independently owned
row result completes. An explicit transaction retains its original snapshot
plus all successful pending statements and reads its own writes. A standalone
write acquires the writer lock, snapshots the current committed head, creates a
pending view, executes the complete row owner, commits and retires before its
ordinary success is returned.

BEGIN IMMEDIATE inside an explicit transaction returns the original nested
transaction category and preserves that transaction. COMMIT and ROLLBACK when
no transaction is active retain their separate ordinary errors. A successful
row call in an explicit transaction returns before COMMIT: this preserves the
existing HIA journal's mutation-ACK-before-COMMIT boundary.

The native row owner already rolls back an unsuccessful statement to its mark.
Constraint failures retain prior successful statements. The frozen 31 queries
were independently prepared using the unmodified official SQLite 3.46.1
amalgamation: every query has `usesStmtJournal == 0`; SELECTs are read-only and
the remaining catalog operations write. Under that exact catalog, the original
VDBE error policy rolls back the whole transaction for NOMEM, IOERR and FULL,
and for INTERRUPT on a write. Read-only INTERRUPT retains the transaction.
This policy is catalog-specific and must be revisited if any query/schema,
trigger or SQLite baseline changes. Physical fault equivalence is a required
remaining composition gate, not established by inspecting the flags alone.

A clean COMMIT with zero changed rows still discards the empty pending view,
retires every transaction/value/view lease and releases the writer lock. It
does not create a synthetic durable transaction. A known SQLITE_BUSY before
head publication during explicit COMMIT retains the transaction for the
caller's deliberate retry, after any prepared-only lease is retired. An
autocommit write failure rolls back its own transaction.

Data sync, head publication, root sync and returned ACK are different facts.
After head publication, a root-sync error refuses permanently with the visible
commit stage preserved. After durable publication, a retirement/unlock error
also refuses; it is not reported as rollback or successful delivery. A lost
publication ACK never starts a new execution or discards allegedly uncommitted
state. A new admitted connection must read the actual committed head/history.
Recovery must preserve unknown requests, budget owners and active leases.

CLOSE rolls back an active uncommitted transaction and closes only after scope
retirement and unlock. Host exception cleanup may release owned descriptors,
but cannot mutate a committed head or invent a native rollback receipt. The
retained context-manager ordering is unchanged: a later ROLLBACK error may
supersede an earlier exception if the original SQLite behavior did so.

## Reference and evidence boundaries

The independent reference input is the frozen ten-table / 31-operation catalog.
The official upstream archive is
`https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip`, SHA-256
`77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784`.
Its source identity is `2024-08-13 09:16:08
c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69a1e33`.
This separately built reference is not the installed retained Python library
and is not counted as HIA execution. Actual retained SQLite observations,
native continuation replay, all physical crash points, and full ordinary
callers remain distinct evidence.

The following are still necessary before activation: all generic values,
affinity/numeric operations, native immutable log/index/view peers, actual
multi-process lock arbitration, exact append/fsync/publication/recovery fault
controls, complete legacy migration including cost high-water and raw storage
classes, and installed no-SQLite/no-host-storage-owner qualification. There is
no new store-wide row/history/byte quota and no shortened public operation set.
