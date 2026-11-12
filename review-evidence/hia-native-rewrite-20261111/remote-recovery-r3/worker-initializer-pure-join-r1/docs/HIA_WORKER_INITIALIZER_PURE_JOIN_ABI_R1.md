# Native initializer pure-peer join, development revision 1

## Status and ownership

This is new, unexecuted authoring. At this checkpoint there are zero AST,
generation, B3, VM, native or ordinary Worker results for this component.
Earlier maps, values, sequencing and other Worker results are separate scopes.

The component consumes an actual pending event of the complete initializer
sequence image. It owns the complete request projection and completion for
TOOLS (peer 2), VALUES (peer 9, all six modes), MAPS (peer 10, all four sequence
operations), and LOOKUP (peer 19). It calls the existing native maps or values
image and returns an exact HIAWIR01 reply. The carrier never constructs a
dictionary/list plan, substitutes a template marker, interprets a schema or
translates a Graph ID into a namespace permission.

The remaining fifteen initializer peer identities remain explicit dependencies:
catalog, installation, namespace open/profile/put/json, Path resolve/is_dir and
root tuple/string conversion, digest, static/file resources, whole verification,
whole renderer and whole assembly. They are not closed by this component.
The source Graph must already contain every foreign value admitted to this
session. Cross-Graph import is a separate native merge/registry obligation.
The first test composition may preload controlled foreign results in a single
Graph, then issue their handles through the actual native ISSUE operation;
that is evidence of a pure-peer join, not evidence of a real Store or of the
ordinary initializer.

## Immutable input and mapping custody

The retained entry is RWW. Internally the second argument is borrowed read-only:
first argument is the current private Graph; second is a private 128-byte command
followed by an actual sequence or child workspace; third is the persistent
private mutable join workspace. The fixed carrier must retain the same
immutable input leases through every replay. Length/header equality is a
correlation check, not cryptographic or external provenance authentication.

The carrier binds all four source/image identities and the actual native entry
return. A result capsule is the actual workspace of the selected child, copied
or borrowed without semantic changes. An arbitrary byte buffer with the same
header is outside this contract. Inputs, child output and join workspace must
be disjoint. When the join emits a prepared Graph in its own workspace, the
carrier must establish an independent immutable child input lease before
calling the child; the join later writes its own workspace.

The actual original initializer input (state-root string and root-string list)
is a different Graph lease from the current value Graph. The join binds both
identities and never treats the latter as the original Path/source authority.

All borrowed result views are consumed or copied before their owning capsule is
released or grown. On a completed Graph-producing child, the fixed carrier
retains the new immutable Graph as the current value lease before retiring the
old one. The native prefix check proves that all old node IDs retain their
values and aliases. A lookup returns a pre-existing source value and need not
retain its temporary appended key.

## Native value handles

Workspace offset 8192 holds an append-only array of 16-byte records:
[root node ID, node count at issuance]. A handle is 2^63 + record index + 1.
These are same-session opaque value identities. Actual namespace/path/program
capabilities are a different issuer and are never admitted as Graph values.

ISSUE accepts an existing valid current Graph node. Reissuing the same node
returns its prior handle. New output roots are issued only after the complete
child Graph, source prefix, event and capacity have passed. The native registry
grows without a new total handle-count or language-node quota; checked u64 and
address-space representation are the only limits introduced here.

Each adopted Graph retains every prior node and edge, with exact old scalar
bytes. Scalar offsets are shifted only by the changed node/edge database size.
The output may append new nodes/edges/pool but may not alter an older value.
Root handles consequently remain meaningful across all later map/value steps.
No digest or nonce is substituted for the actual private issuance relation.

## Private command: 16 little-endian u64 words, 128 bytes

| Word | Meaning |
| --- | --- |
| 0 | HIAWPC01 |
| 1 | 1 ISSUE, 2 START, 3 own-workspace GROW continuation, 4 actual CHILD_RESULT |
| 2–3 | Nonzero initializer invocation and call identities |
| 4 | Current command sequence |
| 5 | Last native join event sequence, initially zero |
| 6–7 | Current value Graph lease and exact byte extent |
| 8 | Exact payload bytes, equal to second-input length minus 128 |
| 9 | Actual observed return: ISSUE 0, START 2304, CHILD_RESULT 640 |
| 10 | Existing Graph root ID for ISSUE, zero otherwise |
| 11 | Nonzero original initializer input Graph lease |
| 12–15 | Zero |

Fresh ISSUE/START is permitted only while idle and uses last completed command
sequence + 1. CHILD_RESULT retains the active command sequence and is accepted
only while waiting for the selected maps/values child. Own GROW repeats the
same immutable command and payload, changing only mode to 3 and the prior event
sequence. Result replay additionally retains the actual complete child event.
No wraparound is allowed.

The initial workspace is at least 8192 bytes and its first 8192 bytes are zero.
The first operation must be ISSUE, which performs the full structural Graph
check before initializing session identity. State offset 32 holds the first
private refusal. Phase 99 permanently refuses later entries.

A too-short workspace can return BAD without access to persistent state.
Event-sequence exhaustion can return BAD without refreshing the event. Every
BAD therefore permanently retires the private session in the fixed carrier;
the caller must not rely on a new refusal frame or attempt to reopen it.

## Join event: 32 words at workspace offset 512

A normal entry returns 768. This is the extent containing the event, not a
language success status.

| Word | Meaning |
| --- | --- |
| 0 | HIAWPE01 |
| 1 | Action |
| 2–5 | Invocation, call, event sequence, active command sequence |
| 6–7 | Initializer peer and exact pending initializer sequence |
| 8 | Required join workspace extent |
| 9–11 | Child kind, last consumed child event sequence, exact required child extent |
| 12–14 | Child input Graph owner, offset, exact bytes; actions 2/3 only |
| 15–16 | Native command/config offset 1024 and bytes 192; actions 2/3 only |
| 17–19 | Completed Graph owner, offset, exact bytes; actions 0/4 only |
| 20–21 | Current adopted Graph lease and exact bytes |
| 22–23 | Initializer reply offset 1280 and exact bytes 256; action 4 only |
| 24–25 | Issued output value handles |
| 26–29 | First private refusal, registry count, original input lease, current node count |
| 30–31 | Selected child mode/operation and zero |

Actions:
0 issued value; 1 grow join workspace and replay the same original input;
2 call the selected child once; 3 grow the existing child and call it again
using the emitted continuation; 4 complete exact initializer reply; 5 refusal,
with actual BAD taking precedence.

Child kind 1 is maps; kind 2 is values. Graph owners for child inputs are
1 = first input and 2 = join workspace. Completed owners are
1 = first input and 3 = second-input capsule. Offset references are relative
to the named buffer, never raw process pointers. Word 8 is relevant to action 1;
a copied prior child sequence in an early join-GROW event is not a new child
request and must not be dispatched.

## Complete sequence association

START carries the actual initializer workspace after its actual return 2304.
The join checks state HIAWIW01, pending status 2 and event HIAWIE01/action 2.
Invocation, call, sequence, phase, peer, pending, workspace need, original source
lease/root, digits, Store handle, operation, all six arguments, raw/literal views,
snapshot location and zero failure words are cross-checked against actual state.
The pending sequence must be newer than the last completed pure peer.

Allowed combinations are exact:
TOOLS phase 3; LOOKUP phase 33;
VALUES (mode,phase) = (1,30),(2,70),(3,73),(4,63),(5,67),(6,60);
MAPS op 1 phase 31, op 2 phase 35, op 3 phase 43, op 4 phases 47/62/69/72.
No unrelated sequence peer can borrow this wrapper.

## Request projection

TOOLS projects the actual catalog handle to native maps operation 1.
MAPS projects empty two-map creation, profile pair update, six initial resource
bindings, and later resource update to maps operations 2/3/4/5.
LOOKUP projects the actual profile-body map and literal key to operation 6.

Every value argument is translated through the native registry. Named keys
come from the actual sequence literal view, not a host-generated key node.
For the six resource bindings, the join checks all six 32-byte rows, exact
sequential key extents and reserved words, then translates all six handles.
It constructs six string nodes, six pair-list nodes and one outer list
(13 nodes and 18 edges) in the private Graph. There is no language quota based
on these intermediate occurrences.

VALUES produces the full existing HIAWVC01 configuration, including all nine
marker IDs. The first four source values are installation, catalog digest,
resolved-root strings and root digest. Mode 3 translates all three actual
profile/artifact/resource handles from the sequence's 24-byte view. Mode 5
requires actual example Core and assembly values. Other modes retain the
original optional later values without prematurely rejecting their absence.

The join reserves two new Graph lease identities once per START, including
lookup. GROW does not reserve them again. Output lease allocation does not
derive from the last adopted lease, so a lookup cannot cause reuse.

## Actual child protocol and GROW

For maps the 192-byte wire is passed unchanged as the child's second input.
For values the 192-byte native configuration is copied to child workspace
offset 128 and the source-bound template packet is the child's second input.
The carrier chooses only this fixed mechanical layout, not a semantic mode.

The child must actually return 640. Its event at offset 512 and state are
checked together: magic, pending identity, mode, status, sequence, need, exact
source extent/lease, native saved source header and complete saved request or
config. Native error/BAD, terminal reuse, unknown action or wrong sequence
retires the wrapper lease.

An actual child GROW must request more than its current workspace extent.
Maps must not publish output roots/views during GROW. The wrapper emits the
next maps CONT wire or the unchanged values config, advances only the consumed
child sequence, and never reenters the initializer, Store or another producer.

At success the complete Graph passes structural validation and exact old-prefix
comparison. New map roots and all internal state counts/extents must match the
actual event. Two-map operations require two distinct map nodes. Values produce
one complete map root. Lookup may return any existing source value appropriate
to the actual fixed profile-body source.

If there is insufficient room to issue output handles, the join emits its own
GROW while retaining the same completed child capsule and event. It neither
reexecutes the successful child nor commits registry/adopted Graph state early.

## Exact initializer reply

The join emits a complete 256-byte HIAWIR01:
invocation, call, original pending sequence and peer; status zero;
kind 2 for one value or kind 8 for two maps; native return observation 640;
one or two native issued handles; zero authority/error/digest/reserved fields;
total extent 256. Only after this complete native reply is available may the
fixed carrier resume the actual initializer sequence.

A map/value is not a namespace capability. Foreign authority fields cannot be
invented by this wrapper, and Graph references never fill namespace authority.

## Planned first qualification

Fresh generation and actual bounded B3 compilation of all four images will use
the preserved 0e09ccca…35591c8 compiler (668608 bytes), original 10 CPU / 20 wall /
256 MiB compile gates and unchanged authoring limits. Each independent runtime
group retains 90 CPU / 180 wall / 1 GiB.

The composition tests will obtain actual events from the complete sequence
image, call the pure wrapper, call the actual selected maps/values image and
feed the exact resulting reply back to the sequence. The unchanged complete
Service constructor/profiles/examples under controlled fifteen-foreign-peer
fixtures is the oracle. Actual pure result values, complete partial attributes,
ordered remaining peer requests, GROW behavior and refusal protocol are compared.
Large values/registry growth have separate groups. This introduces new evidence
only; no previous maps/values/sequence or ordinary Worker counts are inherited.

Each native entry records immutable inputs, full before/after workspace,
actual return and canaries in compressed content-addressed evidence. Exact
source, image, actual compiler receipts, static templates and test code are
pinned before mapping and verified after execution. A failed or killed group
remains FAIL/unfinished with its original last-entry record.

These tests do not certify a fixed native syscall executor, namespace effects,
installation scanning, arbitrary Graph import, all eleven tools or whole Worker
replacement. Those remain explicit work after this pure-peer component.
