# UnixOpen pending to shared-FS native issuance — source revision 2

## Status and exact boundary

This is a new, inactive source checkpoint. No AST check, source generation,
Core verification, B3 compile, VM call, native entry, fixed executor assembly
or physical test has run for this coordinator. The source is not an installed
Store, a completed unixOpen implementation, or an externally authenticated API.

The coordinator replaces the *semantic selection and continuation fields*
currently authored by the Python FixtureIssuer. It accepts private completed
capsules captured from the actual unixOpen parent (runtime role 7) and the
already live shared namespace role 6. It calls the actual raw-effect framer
(role 8), sends that framer's complete request through the same role-6 context,
then calls the framer with the actual completion and publishes its exact
512-byte parent ACK.

A new fixed carrier is still required to issue these capsules from live
contexts and return the final ACK to the actual parent. Current source alone
does not establish that physical producer/caller relationship. It must never
accept the CHILD channel from public input, a Python dictionary, a Graph ID,
an old trace, or an arbitrary byte header. Other unixOpen peers remain pending;
this coordinator does not turn them into successful no-ops.

This branch uses the actual FOLLOW50 FS9/framer component's DMS10 source
closure. The separately published original42 optimization remains exact
DMS9 and its original ten dual-digest proof controls; no fields or results
are transferred between the branches.

## Frozen source dependencies

| Component | Exact Git object |
|---|---|
| UnixOpen parent, original bounded-scan repair | 27868b292476e4049dd1b4194c3524041ea89953 |
| Parent ABI | b7555e912a788d91c63dd193ae7c3d67daea0cd0 |
| Raw-effect framer, exact f0 entry parameters | 01f7821998991a296f81d398670a4a0be8423d42 |
| Shared role-6 registered-FSTAT outer | de8629320367e7e630d671fea433894e4cd0ee28 |
| FS9 | f4f8cb15d40089b98040032367ba53b03bca8b2a |
| DMS10 | 3e82ef42b28e1bd34cf760c2ad229acbafe03e08 |
| Original FixtureIssuer, reference mechanics only | 286ae1565227192ff9f1e4d04fa09890c9bd3280 |
| Generic value authoring primitives | 3d45466a68eca7a88d2352879ea1979848318f63 |
| ObjectBuilder | a188e9553b61ffc4293950908a71a93a3a9a27bb |

No dependency in this table is changed by this checkpoint. No earlier
case count is attributed to the new coordinator.

## Completed-capsule ABI

All scalars are little-endian u64. A completed capsule has a 128-byte header,
then exact original call input, exact full second operand, and exact full
workspace bytes. Lengths cover the full logical operand capacities, not a
header projection. There are no gaps or trailing bytes.

| Offset | Meaning |
|---:|---|
| 0 | HIAUIC01 |
| 8 | Actual runtime role: 6 shared namespace, 7 unixOpen parent, 8 framer |
| 16, 24 | Actual context identity and stable live generation |
| 32 | Actual final native-entry serial, nonzero |
| 40 | Actual returned u32 value, represented in u64 |
| 48, 56, 64 | Original input, full second operand and full workspace byte lengths |
| 72 | Actual immutable input allocation/lease identity, nonzero |
| 80, 88, 96 | Readonly flags: first 1, second 1 only for role 8, workspace 0 |
| 104 | Actual process-context identity |
| 112, 120 | Requesting coordinator action and call identity |

For shared role 6, “original input” is the immutable request that began this
whole outer call. It is not necessarily the last inner image entry's ACK.
The existing carrier preserves that original REQUEST descriptor throughout
the nested DMS/FS continuation. A completed capsule must associate it with
the actual final return/output/workspace from the same live outer context.
The fixed carrier must record both the native entry trace and this association.

For roles 7 and 8 a call is a single image entry. Child GROW does not allow
replacement input, a repeated parent producer, or a fabricated completion.
The carrier may enlarge the child's owned output/workspace while preserving
old logical bytes and then invoke the same actual immutable input.

The initial parent and FS-ready capsules can originate from an enclosing
native controller. Their recorded requesting action/call fields need not
be this raw-join coordinator's fields. Every CHILD capsule consumed here
must match this coordinator's exact active call and action in addition to
role/context/generation/entry serial and complete issued input.

These fields correlate private issued views. They do not prove the source
of an externally supplied buffer.

## Private input channel

The input channel has a 256-byte header beginning HIAUIX01.

### BEGIN, command 1

Offsets 16/24 are the coordinator scope pair, 32 its call sequence, 40/48 its
actual context/generation, and 56 the actual process context. Offsets 64/72/80
are the existing framer context/generation/last actual entry serial. Offsets
88/96 are the two complete capsule sizes. Bytes 104..255 are zero.

The tail is the actual role-7 pending capsule followed by the actual role-6
ready capsule. The parent must have returned 1 with a coherent pending
header and phase-2 workspace. The shared FS outer must have returned 0 with
phase-1 ready workspace. The fixed carrier must capture these without running
an unrelated operation between the capture and the issued continuation.

A fresh raw-join context starts at call 1 and a fresh framer entry serial 0.
Later BEGIN calls require call+1, stable context/generation/process bindings,
a strictly newer parent entry, a later parent action within the same parent
call, and nonregressing actual role-6 entry serial. The framer serial must
equal the last one this coordinator consumed. Completed non-raw pending
calls do not advance the separate framer-call sequence.

### CHILD, command 2

Offsets 16..56 repeat the current coordinator scope/call/context/generation/
process. Offset 64 is the currently issued action, 72 the complete capsule
size, and 80..255 are zero. The only tail is the actual completed capsule.

Its role/context/generation must equal the issued target; its entry serial
must increase; its recorded requesting call/action must exactly match.
The complete original input must equal the retained issued request. For the
framer its readonly second operand must also equal the complete issued peer
descriptor, with no byte masking.

## Native state and actions

The workspace has a 1,024-byte fixed prefix followed by an append-only,
derived-capacity region for the exact parent/framer request bytes and peer
capsules. It has no new filename or Store-record quota. Arithmetic checks
prevent u64 offset/length overflow before any append or read. The original
native address-space and VM budgets remain separate required gates.

Phases are BEGIN-GROW=1, framer-BEGIN=2, shared-FS=3, framer-COMPLETE=4,
ACK-published=5, other-peer-pending=6, and permanent refusal=7.

The root scope/call sequence and the framer's call sequence are distinct.
A new raw action increments the latter exactly once, after the root has
enough space to retain its inputs. Replaying root GROW or framer GROW cannot
increment it twice. A non-raw pending output does not consume it.

The HIAUIE01 output is exactly 256 bytes:

| Offset | Meaning |
|---:|---|
| 8 | 0 exact parent ACK ready; 1 actual child call; 2 grow coordinator; 3 unresolved other peer; 0xfffffffd permanent refusal |
| 16..64 | Coordinator scope, call, context, generation, process and issued action |
| 72 | Current coordinator phase |
| 80 | Issued actual child role for CALL |
| 88, 96 | Issued first view offset/length in this workspace |
| 104, 112 | Issued second readonly view offset/length; zero for shared role 6 |
| 120, 128, 136 | Expected child context/generation and previous entry serial |
| 144, 152 | Child second-operand/output capacity and workspace minimum |
| 160, 168 | Required coordinator workspace and output capacities |
| 176, 184 | Exact published ACK or unresolved parent-pending view offset/length |
| 192 | First permanent refusal reason |
| 200 | Original unixOpen effect operation |
| 208..240 | Actual parent context/generation/entry/call/action |
| 248 | Reserved zero |

Status 2 means enlarge this coordinator's storage and replay its identical
current immutable input. It must not reissue a completed child. Status 1
selects only role 8 or the existing role 6. The carrier validates every
logical span and its permissions before copying or invoking anything.
No raw address or FD is selected by these public bytes.

## Exact raw route

The framer remains responsible for mapping the eight parent operations:
GETPID, ACCESS, GETEUID, FCHOWN, UNLINK, CLOSE, late FSTAT, and late STAT.
The coordinator neither supplies syscall results nor duplicates that mapping.

It constructs the framer's first input from the full actual parent pending
output and its second input from the actual shared-FS workspace. On the
framer's pending result it copies only the exact issued request span,
including the complete private HIANDJX1 channel, and calls that same shared
role-6 context. On actual completion it constructs the framer's final peer
descriptor from the original request, exact logical outer result, and full
actual workspace. It changes only the framer input command 1 to command 2.

The final 512-byte ACK must be the actual framer output. Its parent scope,
call, action and original 256-byte request copy are compared with the saved
actual parent output. Its FS/context/generation/serial/source-lease fields
are checked against this exact completed role-6 result. Only then is the
ACK view published for a native caller to feed to the existing parent.

Error-valued successful FS frames retain the original parent/framer errno
rules. The coordinator does not add a rollback, implicit retry, default
success, or a host-selected branch. Child protocol refusal permanently
poisons this coordinator.

## r1 to r2 authoring corrections

Both sources are unexecuted and preserved. Pure source review found that a
non-raw pending call must not consume a framer sequence number; r2 tracks
that number separately. It also binds the completed capsule to the exact
coordinator call as well as its action, and checks all retained workspace
spans/phase-specific target bindings before following offsets.

The inverse textual changes recover r1 exactly. This is not an executed
counterexample, a generation pass, or a proof of every possible workspace.

## Required next integration and gates

The missing fixed-carrier work is concrete: stable role-7/8/9 contexts; capture
of actual call input/output/workspace after completion; independent context
and entry generations; immutable call descriptors; child GROW preservation;
role-6 entry into the existing nested continuation and return without an
extra OS process; and exact ACK transfer back to the live parent. External
input must not provide completed capsules or arbitrary ACKs.

The next actual joint gate must use the exact source/image closure and retain
the existing original raw-effect/framer semantic and protocol cases, plus
new real-producer/capsule sequencing cases, non-raw interposition, GROW,
failed raw effects, altered generation/call/action, replay and partial-failure
cleanup. Full original return/operand/workspace comparison is required for
paired HIA windows, not masked header equality.

B3 gates remain 10 CPU / 20 wall / 256 MiB / 1 MiB output and workspace.
Native subjects retain 90 whole-process-tree CPU / 180 wall / 1 GiB / core 0.
The original 900-second aggregate, 4,000,000 VM steps, 32 MiB VM arena,
call-depth 64, and the original authoring profile/SSA gates must not increase.
Any new CI must measure the complete phase including final source-after
checks, keep failed originals, and publish the generated canonical .hiaasm
and actual image bytes. No such CI is included or claimed by this checkpoint.

Other unixOpen peers, durable high-level put/get, all 31 SQL operations,
migration, multiwriter transactions and the ordinary Worker remain open.
