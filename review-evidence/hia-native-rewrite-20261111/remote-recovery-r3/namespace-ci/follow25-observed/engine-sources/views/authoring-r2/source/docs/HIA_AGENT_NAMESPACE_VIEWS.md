# Immutable commit and paged view coordination

This is the next implementation surface after the frozen record codec r2.
The existing transaction, row, scalar and object ABIs remain the complete
interfaces. This document does not declare an installed namespace, successful
physical qualification, or completed legacy migration.

## Storage and snapshot ownership

The physical data stream is an append-only sequence of the already specified
HIANLR01 records. A committed view owns an actual data-file lease and a precise
committed prefix. A pending view owns a separate transaction spool and a precise
prefix of that spool. A cursor captures both extents at its creation; appending
a later UPDATE cannot change the rows already being scanned by that cursor.
Fresh uniqueness checks can create a new cursor over the later pending extent.

The committed namespace is not loaded into a bounded memory arena. HIA asks for
small exact file ranges, validates every returned range and chooses subsequent
offsets. The mechanical I/O executor performs those requested reads, reports
actual short reads/errors and keeps descriptor leases. It does not enumerate,
filter, order, normalize or select records. An arbitrary caller-supplied file
descriptor, matching header or hash is not an admitted namespace lease.

A snapshot's prefix remains immutable while later commits append beyond it.
The same data-file inode may therefore have a later size/mtime. Validation must
bind the actual descriptor, namespace identity, committed prefix and native
publication history rather than incorrectly demanding that the whole mutable
append-file stat tuple never changes. Truncation below any committed prefix,
replacement of the data inode, and a mismatched namespace epoch are refusals.

## Complete row view semantics

The native reverse walker first visits the captured pending prefix, then the
captured committed prefix. Each record footer supplies a checked total span;
the native owner checks the matching full header, exact range, table and kind.
A record location is an internal tuple of the actual file lease, snapshot
generation, header offset and exact extent. It cannot outlive its issued view.
Returned row bytes subsequently pass the complete record codec and object/value
admission before they become an independently owned result.

For signed-rowid order, the native selector chooses the smallest rowid above
the cursor's previous boundary. Reverse history means the first occurrence of
that rowid is its latest record, including a tombstone. An older equal-rowid
record never replaces the chosen newer record. If the selected latest record
is a tombstone, the owner advances its boundary and continues; no hosted set of
seen rowids or entire-namespace cache is needed.

For the versions primary-index order, the full key is slot, generation, then
signed rowid. A candidate must first be resolved to the latest actual rowid
record; stale historical keys cannot participate in ordering. Key comparison
uses all five classes and the existing exact INTEGER/REAL and BINARY semantics.
Large TEXT/BLOB keys are compared in bounded byte windows. No field, namespace,
record-count or history limit is introduced to simplify the scan. A future
index may accelerate these selections only while preserving this complete
observable order and ownership.

Rowid allocation consumes the actual latest view, not row count. An empty table
starts at1; a nonempty table with a negative largest rowid increments that signed
value. Non-AUTOINCREMENT exhaustion uses the retained SQLite 3.46.1 random
candidate rule and its existing100-probe behavior. Costs also consume the exact
stored sequence cell through the retained integer conversion; TEXT-prefix
conversion here must not be replaced with NUMERIC affinity. Statement rollback
restores both the pending extent and cost sequence state.

## Actual commit ordering

An owned namespace writer lock serializes native writers. After obtaining it,
the native owner reads the actual current head and captures the base view. A
prepared transaction validates and hashes its exact record spool through the
native codec and stream hash, appends only to the current data-file tail, and
constructs its new canonical head. The head binds namespace identity, epoch,
old/new committed extents, the appended bytes' digest and the preceding head's
digest. Persistent commit identity is content-linked, not a bounded global
transaction counter.

The following remain separate issued operations: data write completion, data
fsync, creation and fsync of the new head object/temp, rechecking the current
base head under the same actual lock, atomic head replacement, and root-directory
fsync. The frozen transaction owner receives each real boundary in its original
order. No returned success may be inferred merely because the expected file is
present. An unknown publication acknowledgement poisons the current owner;
another admitted session must inspect the actual head instead of replaying the
write. A known pre-publication failure leaves the previous committed prefix
authoritative. Any uncommitted tail is ignored until an actual locked recovery
operation reconciles it; committed prefixes are never truncated by retirement.

Read-only calls still receive distinct call/view generations. A zero-change
COMMIT discards its pending scope and releases the lock without publishing a
synthetic commit. Independently owned row results survive view retirement.
Closing a descriptor is mechanical cleanup; it is not a native rollback or a
commit receipt. The existing HIA journal's intent/ACK/replay decisions are reused.

## Migration and writer fencing gate

The native writer lock alone does not fence an old SQLite process. A rename or
chmod alone also cannot revoke an already open old descriptor. Ordinary native
selection remains disabled until a real migration protocol proves the old
writer lifecycle and the complete five-class/rowid/sequence copy.

The implementation must distinguish draining known managed old workers from
merely observing a lock. A future migration guard must also stop new ordinary
old opens while it drains existing handles, preserve the old database and a
durable recovery state, and recover safely if its process dies at every step.
An unaccounted old writer or incomplete ownership observation keeps migration
on HOLD. A metadata timestamp window is not proof of who wrote or removed data.

The first physical controls will use actual isolated files and independent
processes: concurrent snapshot readers, competing native writers, stale base
heads/epochs, all real append/fsync/rename boundaries, short I/O, lost ACK and
process death. Legacy-writer tests must demonstrate the actual fence/drain
behavior; they cannot substitute a mocked successful lease or an always-true
callback. No production source or original qualification output is changed by
these development fixtures.

## First executable view component

The `HIANVW01` component implements the two complete cursor orders above. It
does not yet allocate rowids, publish heads, acquire a writer lock, migrate a
SQLite file, or select the ordinary namespace path. Those remain explicit work
for the surrounding complete engine. Its source includes the six exact scalar
comparison routines from the separately frozen native comparison component.

It has one read buffer, a 256-byte minimum output descriptor, and a fixed
12,288-byte private workspace. All file requests are at most 4,096 bytes. The
workspace contains two byte windows and fixed metadata; neither a whole key
nor a list of namespace rows is retained. Persistent logical history is bounded
by the actual platform file range, not by a new record-count or field-size cap.
Session calls and issued read actions use the existing checked u64 transport
counters, with refusal before wrap. A new cursor receives a new issued view
generation even when its transaction sequence has not changed.

Inputs begin with twenty little-endian u64 words. BEGIN is command 1 and binds
`magic, command, sessionLo, sessionHi, call=1, 0, 0, 0, namespaceLease,
viewLease, rowGeneration, table, order, pendingFileLease, pendingPrefix,
committedFileLease, committedPrefix, 0, 0, 0`. The namespace, view and generation
must be nonzero. A missing pending descriptor requires a zero pending prefix;
an actual committed descriptor exists even for an empty namespace. The two
descriptors are distinct. These are private leases issued by the surrounding
native owner, not authentication of arbitrary outside files or copied handles.

NEXT (command 2) and CLOSE (command 4) use the same magic/session, the next exact
call, and fifteen zero trailing words. A read ACK is command 3:
`magic, 3, sessionLo, sessionHi, sameCall, issuedAction, 1, status,
fileLease, exactRequestedOffset, returnedBytes, viewLease, rowGeneration,
errno, 0, 0, 0, 0, 0, 0`, followed by precisely the returned bytes. Status 0 is
an actual completed read. A positive short read requests the remaining range
with a new action identity. A zero read before the captured extent produces
IOERR_SHORT_READ (522). Status 1 carries a real errno: EINTR requests the same
remaining range with a new identity; other errnos produce IOERR_READ (266).
Status 2 is an unknown acknowledgement and permanently refuses the owner.
It is never converted into a safe retry of an unconfirmed operation.

Output is thirty-two words: magic, status, session pair, call, action sequence,
continuation phase, pending action, file lease, offset, remaining bytes, view
lease, row generation, table, order, returned row file/offset/span/rowid/kind,
error code, refusal reason, errno detail, namespace lease, state, EOF flag,
ABI version 1, and five zero words. Pending action/range is present only for a
real read request (status 1). Status 0 means BEGIN/CLOSE completion or a returned
row; status 3 is EOF; status 2 is a known physical failure. Returned-row fields
are cleared before a new NEXT, at EOF and on a physical failure. `0xfffffffd`
is persistent refusal. A known physical failure allows only CLOSE; unresolved
I/O cannot be silently abandoned and restarted with a NEXT on the same owner.

The private state validates the exact continuation's file and range, the
outstanding action, capture extent, workspace buffer and completion marker.
An active-to-idle state-word mutation alone cannot license another NEXT. These
checks are consistency checks on a private live workspace, not a claim that an
arbitrary attacker-supplied full workspace can authenticate its own history.

Record discovery verifies full framing and table/kind/extent metadata. The
two key cells are validated before they participate in index order. The entire
returned row still passes the existing complete native record/value admission;
the view does not assert that reading only a record header validated an unread
non-key payload. This distinction is retained in actual-file and malformed-file
tests. Source/model execution, actual B3 execution, and full physical-store
qualification must remain separate evidence categories.
