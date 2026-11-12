# Initializer Graph import, value registry, and configuration peer — revision 1

## Status and authority

This is new development source. At this checkpoint it has not been AST-parsed,
generated, compiled, or executed. It does not inherit the execution results of
the separate initializer sequence, values, maps, pure join, or Graph merge tests.

The proposed actual composition has six freshly compiled images: initializer
sequence, pure join, maps, values, this registry/configuration peer, and the
unchanged original Graph merge. The complete original Service constructor,
_profiles, and _examples remain the independent oracle. The fifteen effectful
or external semantic peer identities remain explicit foreign fixtures. Store,
filesystem, installation admission, arbitrary program verification, assembly,
fixed syscall execution, and the ordinary Worker are not closed by this gate.

An issuer holds each source Graph, original initializer arguments, and actual
child workspace as a private immutable lease. Header/extent correlation does
not authenticate attacker-supplied bytes. A value handle is an identifier in
this one private invocation, never a namespace, path, file, transaction, or
program capability. No digest is substituted for authority.

## Existing components remain unchanged

The original merge authoring is 11,265 bytes, Git object
9eea9deec088878dc5889d8218e7b422c73efea3, SHA256
b4cda58e84da76a17a2daa919f37483eb2973dcfdbb00cd30c074ebc9aca8ed9.
It was recovered byte-for-byte from the published R13 archive. The new tests
compile it with the original f50 B3 image, rather than copying an unrelated
image or changing its private wire format.

The frozen pure join uses HIAWPC01 / HIAWPE01 / HIAWPW01. Its eight source,
documentation, and test files are unchanged. This new peer shares its issued
value registry and command/event counters, and uses previously unused fixed
scratch between offsets 4096 and 5248. The initializer input remains a
separate immutable source lease; importing values does not rewrite its IDs.

The original Graph merge creates a new root [selectedLeft, selectedRight].
All left node IDs move by 1, all right node IDs by leftNodeCount + 1, and both
complete scalar pools and all edges are retained. Cycles and aliases inside
each input remain represented. Independent leases do not imply cross-lease
object identity. If an actual provider intends to return an already issued
object it must return that issued handle; recapturing it as an unrelated
foreign lease is not an identity proof.

## Native ownership

This image owns bootstrap configuration, global value-Graph lease allocation,
complete old merge command construction, all required merge continuations,
actual merge event and workspace correlation, full relocated Graph validation,
all existing handle relocation, imported handle issuance, and GraphWire
configuration for a selected issued value.

The carrier only forwards exact byte views, calls a fixed image, grows a
workspace without changing its existing bytes, and copies a completed view
before its lease expires. It must never enumerate a Graph to decide what to
merge, change stored node IDs, synthesize merge results, choose the imported
root, or derive initializer/GraphWire configuration from Python values.

Foreign values are imported at the actual provider return point. The new
composition tests do not preload future values into one Graph. The controlled
fixture remains responsible for issuing its own foreign source Graph; this
test issuer is not an implementation of ordinary Store.

## Entry and command

The retained machine ABI is RWW; the wrapper borrows the second input as
read-only. Internally:

- s: the current immutable complete Graph; at BOOT, the actual initializer
  argument Graph.
- r: a 128-byte command plus the exact indicated payload.
- w: the private shared pure/registry workspace, at least 8192 bytes.

The complete command is 16 little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAWGC01 |
| 1 | Operation: BOOT 1, RESERVE 2, IMPORT 3, MERGE_RESULT 4, CONT 5, BORROW 6 |
| 2, 3 | Nonzero invocation and call identifiers |
| 4 | Shared command sequence |
| 5 | Previous shared event sequence |
| 6, 7 | Current Graph lease and exact bytes |
| 8 | Exact payload bytes, equal to length(r) minus 128 |
| 9 | Actual child return: 384 only for MERGE_RESULT; otherwise zero |
| 10 | Issued value handle only for BORROW; otherwise zero |
| 11 | Integer digit policy only for BOOT; otherwise zero |
| 12 | Original initializer source lease |
| 13 | Foreign Graph bytes for IMPORT, CONT, or MERGE_RESULT; otherwise zero |
| 14 | Actual merge workspace bytes only for MERGE_RESULT; otherwise zero |
| 15 | Zero |

BOOT requires all first 8192 workspace bytes to be zero, command sequence 1,
previous event sequence 0, no payload, and current/source lease equality.
It validates the complete issued Graph before writing any initializer config.
The digit setting is zero or at least 640, preserving the original configured
integer policy rather than imposing a new fixed language maximum.

Idle RESERVE and BORROW require last completed command + 1. Each actual entry
advances the shared event sequence once. An outstanding import keeps the same
command sequence until its full result commits. Own CONT and actual child
continuations use the same immutable inputs and the latest acknowledged event
sequence. A pure join operation and a registry operation cannot be interleaved
inside one another's pending phase.

## Bootstrap and selected-value configuration

BOOT writes 192 bytes at workspace offset 1024:

    [HIAWIC01, invocation, call, sourceLease, sourceBytes,
     sourceRoot, digits, 0, ... 0]

The caller copies those exact bytes into the unchanged sequence workspace
configuration at offset 128. It does not reconstruct these fields.

BORROW validates a previously issued value handle and writes 64 bytes at 1024:

    [HIAGWC01, currentGraphLease, commandSequence, selectedRoot,
     8388608, 2, digits, 0]

This is the original Store wire profile: ensure_ascii=False and sorted keys, with
the original integer digit setting. BORROW does not serialize the Graph or
enforce the wire byte limit. The consumer invokes GraphWire only at the
original semantic call site. Import itself has no 8 MiB or 262144-node cap.

## Import protocol and commit point

RESERVE issues two never-reused private Graph lease numbers: a foreign input
lease and the future merge output lease. It does not publish a new value
handle. The provider receives only the appropriate private issuance contract.
If the provider fails, the enclosing initializer is retired; no cancellation,
implicit retry, or successful import is invented.

IMPORT receives the complete foreign Graph after the 128-byte command. It
validates all nodes, edges, shape, scalar extents and canonical integer
representation under the existing private issued-Graph contract. It then
reserves space for one more registry record and the complete old merge command
plus current Graph. Insufficient local capacity yields OWN_GROW. CONT retries
this component only; it must not repeat the provider or initializer.

The complete old merge first input is:

    [HIAGMC01, 1, newGraphLease, commandSequence, 0,
     currentRoot, foreignRoot, 0, ... 0] + currentGraph

Its second input is the exact foreign Graph; the actual child workspace
starts as zeroed 512 bytes. A child GROW produces the old mode 2 command with
the actual previous child event sequence. The same complete two sources are
retained. The provider is never reissued.

MERGE_RESULT receives foreignGraph + actualCompleteMergeWorkspace. It checks
the actual return 384, exact extent, the entire 512-byte state/event/header
area, counter and lease identities, required capacity, selected roots, and
all reserved fields. Child GROW cannot claim success at insufficient capacity.

On DONE it validates the complete output Graph, root pair, every relocated
left and right node and edge, and both full scalar pools. All previously
issued registry rows are validated before any relocation is committed.
Only then does it add 1 to each existing selected root and its issuance node
count, issue the imported root under its new opaque handle, adopt the new
Graph header, complete the command, and return to idle.

A result failure is private ABI refusal, not a new public language diagnostic.
No issued handle, current Graph, or completed command is partially published
by a failed validation. Internal scratch and event/failure state may change.

## Event

A successful transport entry returns 768, with a complete 256-byte event at
workspace offset 512. The 32 little-endian u64 fields are:

| Word | Meaning |
| --- | --- |
| 0 | HIAWGE01 |
| 1 | Action: BOOT 0, OWN_GROW 1, RESERVED 2, CALL_MERGE 3, GROW_MERGE 4, BORROW 5, IMPORTED 6, REFUSE 7 |
| 2, 3 | Invocation and call |
| 4, 5 | New shared event sequence and active command sequence |
| 6, 7 | Current complete Graph lease and bytes |
| 8 | Required own workspace capacity |
| 9, 10 | Reserved foreign and output Graph leases |
| 11, 12 | Last consumed child event sequence and required child workspace |
| 13, 14 | Complete merge input offset/bytes in w, for CALL_MERGE/GROW_MERGE |
| 15, 16 | Foreign Graph offset/bytes in r, for CALL_MERGE/GROW_MERGE |
| 17 | Completed Graph view owner: 1 = s, 3 = r |
| 18, 19 | Completed Graph view offset/bytes |
| 20, 21 | Selected root and issued value handle |
| 22, 23 | Configuration offset/bytes: BOOT 192, BORROW 64 |
| 24 | Total issued value count |
| 25 | Original initializer source lease |
| 26 | Current Graph node count |
| 27 | Private refusal reason |
| 28 | Zero |
| 29 | Last completed shared command |
| 30 | Internal phase |
| 31 | Zero |

Only fields active for the action are views. Before growing, reusing, or
releasing an owner workspace, copy any view still needed. IMPORTED's Graph is
inside the submitted actual-child result at
128 + foreignBytes + 512. The original merge workspace and exact submitted
view must remain immutable through validation and extraction.

## Refusal and lifecycle

BAD is 0xfffffffd and takes precedence over any event header. A complete
accessible workspace is poisoned by phase 99; later registry and pure calls
refuse. If the advertised workspace is shorter than 8192, native code cannot
safely reach the persistent state and returns BAD without writing poison.
Event counter overflow may also leave an old event frame. The fixed caller
must permanently discard the lease on every BAD before looking at a frame.

There is no reset operation. BOOT cannot reopen a dirty or completed session.
Lease/command/event overflow refuses rather than wrapping. Temporary child
views are scoped to the current exact invocation and pending command. Handles
from another invocation, low numeric Graph IDs, and unissued high IDs refuse.

## Planned verification and limits

The new driver will preserve complete source before/after pins, compiler
receipts, full input/workspace bytes, canaries, per-entry ledgers, pending-entry
frontiers and original exceptions. Actual initializer traces, partial
attributes, alias relationships and first errors will be compared with the
unchanged complete original methods. Independent controls will change command
identity, workspace size, output layout, child counters, node/edge/pool bytes,
and replay state. Every bad accessible state will be checked for permanent
refusal; short workspace is explicitly outer-retirement scope.

The original f50 B3 is 668608 bytes with SHA256
0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.
Each fresh compile keeps 10 CPU seconds, 20 wall seconds, and 256 MiB.
Each actual test group keeps 90 CPU seconds, 180 wall seconds, and 1 GiB.
Large private Graph controls retain values above 8 MiB and node inventories
above 262144; they do not introduce new intermediate quotas. Any timeout,
failure, or unexecuted group is retained as such.
