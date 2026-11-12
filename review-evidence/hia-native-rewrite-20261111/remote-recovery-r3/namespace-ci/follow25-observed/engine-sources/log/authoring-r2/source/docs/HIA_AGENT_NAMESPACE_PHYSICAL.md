# Native namespace physical records and execution composition

This development revision continues the complete ten-table, 31-operation,
51-call contract. The completed value, row, transaction, comparison, affinity
and transient-object components are unchanged. No ordinary AgentStore selector
changes here, and SQLite migration and old-writer fencing remain open.

## Physical design and remaining ownership

Committed data will use immutable segments addressed by the actual HIA stream
hash. A published head binds the complete segment and its parent head. A
writer must hold the actual namespace writer lock while preparing a segment,
syncing its bytes and directory, comparing the base head, atomically publishing
the new head and syncing the namespace directory. Those are separate physical
observations; an unknown acknowledgement cannot turn into rollback or retry.
The existing transaction owner decides these transitions. The existing HIA
journal continues to decide request intent, mutation ACK, replay and completion.

An immutable read view owns the actual head and segment descriptors. A pending
view adds only its current transaction's unpublished records. A statement mark
binds the pending extent and sequence state; rollback restores that exact mark.
Every public call gets a fresh lease generation even if the committed head did
not change. A clean COMMIT releases its pending/view/value leases and lock.

The native view, rather than a hosted iterator, must choose the latest record
for each signed rowid, rowid order, the complete versions primary-index order,
NULL/storage-class/BINARY key comparison, rowid allocation and cost high-water.
Only the currently visited value/row and retained result need transient RAM.
The committed namespace and its history must not be loaded into a fixed-size
arena or truncated at a new row/byte/history quota. An initial streaming scan
is permitted; any later index must preserve the same complete semantics.

The fixed mechanical executor may open an HIA-selected relative component,
read or write an exact requested range, acquire/release the issued lock, sync,
rename and report the actual result. It must not choose a row, normalize a
value, infer successful publication, mint a semantic object, or provide SQL.
Native framing/lease fields are internal correlation, not authentication of
arbitrary external files or buffers.

## Record format, revision 1

The record codec is the first physical component in this revision. It does not
by itself implement segment chaining, read views, file durability or migration.
Each record is a 64-byte header, exact payload, and a 16-byte footer. All fixed
words are unsigned little-endian 64-bit words; rowid uses signed two's-complement
bits. The header is:

    [HIANLR01, 1, kind, table, rowidBits, payloadBytes, recordBytes, 0]

The footer is `[recordBytes, HIANLR01]`, and recordBytes is exactly
`64 + payloadBytes + 16`, with checked representability. Kind1 is a whole-row
replacement, table1..10. Its payload is count:u64 followed by the existing
five-class cell envelopes, and count must equal that table's complete width.
Kind2 is a row tombstone, table1..10, with no payload. Kind3 preserves the
cost sequence cell, table5 and rowid0; its payload has exactly one cell. Keeping
all five classes here avoids silently narrowing a legacy sequence value before
the future native allocator applies the retained SQLite conversion rules.

NULL has no bytes, INTEGER/REAL have eight, and TEXT/BLOB have their exact raw
extent. This codec neither repairs UTF-8 nor applies affinity. The actual
object/row owner supplies normalized stored values. A format-valid private REAL
NaN does not prove that an ordinary SQLite-equivalent row has been admitted.
There is no whole-record allocation: headers and envelope state fit in a fixed
workspace while arbitrary present chunks stream through. Counter or extent
overflow refuses the current transport; it is not a new namespace-wide quota.

## Private codec protocol

The RWW entry uses input128+, output192+, workspace1024. Frames have 16 words:

    [HIANLG01, command, sessionLo, sessionHi, operation, sequence,
     sourceLease, recordLease, kind, table, rowidBits, payloadBytes,
     offset, chunkBytes, 0, 0]

The session pair is nonzero. BEGIN_ENCODE1 starts the next operation with
sequence0 and a strictly increasing actual record lease; kind/table/rowid/size
are declared and the remaining fields are zero. It emits the exact 64-byte
header. ENCODE_CHUNK2 uses the same metadata, next sequence, exact payload offset
and a nonzero private immutable source lease; its appended bytes follow input128.
The complete chunk is structurally validated before output capacity is tested.
It emits that exact validated chunk, which remains unpublished pending data.
END_ENCODE3 requires every declared envelope and byte, uses the next sequence,
zero source lease/chunk, and emits the footer before completing the operation.

BEGIN_DECODE4 starts the next operation with a new record lease and zero
metadata. DECODE_CHUNK5 feeds the actual complete record stream at its exact
offset, with a nonzero immutable source lease. Header, payload and footer may
split anywhere. No completed record descriptor is published before END_DECODE6
checks all bytes, complete envelopes and exact footer. Decode does not allocate
or return the whole payload. CLOSE7 is allowed only between records; a closed
codec cannot be restarted.

Status0 completes a record/close, MORE2 keeps the record active, GROW1 asks for
the precise output capacity, and BAD0xfffffffd permanently refuses a usable
workspace. GROW leaves logical parser state, operation and sequence unchanged.
The retry must use the same actual immutable source allocation and exact frame.
Only the fixed coordinator can enforce that private allocation lease; matching
numeric headers alone do not authenticate substituted external bytes. A short
workspace cannot store poison and must be discarded by the executor.

The output24 words are magic, status, session pair, requested operation and
sequence, command, record lease, codec mode, kind, table, rowid, payload bytes,
consumed payload, consumed input, record bytes, emitted bytes, required output,
first reason, phase, expected value count, completed value count, revision1,0.
Only the emitted range after byte192 is meaningful; all remaining output bytes
are zeroed. Incomplete validated data belongs only to the unpublished temporary
record, never to a committed view. Any later refusal discards that candidate.

Authoring revision2 records an explicit completed-record marker written only
by END, and requires idle state to have that marker, a complete header/footer
and complete payload. Revision1's full ordinary corpus passed before separate
real-image private-workspace probes changed active phase2 to idle phase1. That
could discard an incomplete header, an unwritten footer, or complete decoded
bytes that had not received END. All three original counterexamples and the
unchanged revision1 source/image remain retained. These are explicit private
state-integrity controls, not claims that an ordinary caller owns the workspace.
The complete original corpus plus those controls is rerun against revision2.

## Required evidence before ordinary activation

The record codec must have actual B3/native and complete-workspace VM controls
for every byte split, all schemas/classes, malformed headers/footer/lengths,
large streamed TEXT/BLOB, GROW/replay, counters, source stability and permanent
refusal. Following work must compose native snapshot/index/pending selection,
all 31 row operations, actual lock/fsync/atomic-publication faults and replay,
concurrent readers/writers and complete migration. Existing old SQLite writers
cannot be fenced merely by renaming a file or adding a new cooperative lock.
Until those gates pass, the old ordinary path remains selected.
