# Native CLI business contexts — ABI r3

Status: NEW / UNEXECUTED implementation contract. This document extends the seven-image development
entry; it does not activate the installed CLI, replace old business owners, or
claim that operation 17 is already implemented. The original seven-image source
and its first CI failure remain separate originals.

## Ownership and finite call graph

The parent CLI HIA owns option selection, file-read order, CLI exception
presentation, output selection and publication orchestration. The service HIA
owns program admission and the selected business operation. The executor owns
only fixed image tables, contexts, mappings, checked read-only leases and ACK
transport. It must not inspect JSON, split fields, select functions, interpret a
schema, or synthesize a semantic diagnostic.

A CLI process has at most one active service sibling. Each context has its own
64-slot table, fixed image table, command/frame mappings, controller workspace,
lease and sequence. The permitted graph retains existing bounded nesting:

- CLI role 7 -> service root role 56, selected by a compiled service-table ID.
- The selected service retains its already verified edit/program internal
  edges: service 56..59 -> PROGRAM 46 -> ordinary 43/40..42/45.
- No edge permits an arbitrary role table, user-supplied code, a second active
  service sibling, or recursion back to the CLI.
- Actual allowed role/mode edges and initial capacities must be imported from
  the exact restored executor and source-bound service bundle. This draft does
  not infer them from a filename index.

Service table 1 is parent-owned program inspection/normalization; table 2 is
parent-owned edit query/application. Other action families remain unsupported
until their complete real owners have a separate fixed table and tests.

Table 1 assigns the program projector to component role 60, not controller role
57. Its second command lease is physically read-only: the root table-1 mask is
0xf0bf80bee2ac0462. Only actual role 56 can CALL this A projector. Table 2 retains
0xe0bf80bee2ac0462, including role 60's original writable second operand. Internal
program/ordinary contexts retain the original mask and guards. The old CALL
exclusion for controller roles 56..59 remains unchanged.

## Parent operation 17

The existing HIACDE01 event and outer parent lease/sequence remain unchanged.
In the new revision its twelve argument words are:

| Argument | Meaning |
| --- | --- |
| 0 | verb: 1 BEGIN, 2 RESUME, 3 RETIRE |
| 1 | fixed service-table ID |
| 2 | nonzero service-context lease |
| 3..5 | parent read-only command slot, offset, bytes |
| 6..8 | parent read-only lease-table slot, offset, bytes |
| 9 | parent output slot for an exact copied child yield view |
| 10 | expected previously yielded child sequence; zero for BEGIN |
| 11 | zero |

BEGIN requires no active service. RESUME/RETIRE require the same active
service ID/lease and the exact previous child yield sequence. Parent command
sequence still advances once per issued operation, independently of child
sequence. A GROW or slot-copy acknowledgement cannot count as another service
BEGIN or resume. RETIRE accepts no input leases and performs no HIA business
call; it destroys owned child mappings, leaves borrowed parent mappings intact,
unpins all parent sources and returns an empty transport ACK.

The destination must be a nonreserved parent-owned slot not present in the
input leases. Validate all command and lease spans before allocating or changing
the active context. Copy the completed child view into a fresh exact logical
parent mapping, protect it read-only, and only then acknowledge operation 17.
This preserves the view after any later child resume, growth or retirement.

## Mechanical lease table

The table header is 32 bytes (four u64): HIALSV01, version 1, row count, total
bytes. It is followed by exactly rowCount 32-byte rows:

[parentSourceSlot, sourceOffset, sourceBytes, childTargetSlot]

The private per-entry transport admits at most four rows. This is a fixed
context-installation arity, not a quota on source size, JSON nodes, calls, or
program language. All rows are read-only and bounded in the actual parent slot;
duplicate child targets and aliasing a mutable command/frame/workspace are
rejected before any child call.

BEGIN installs input program at child slot 1, complete captured argv packet at
child slot 4, and complete issued parser workspace at child slot 5. No executor
interprets the 16 parser field rows. These three immutable source spans are
selected by the parent HIA and consumed by the service HIA.

A service can discard its initial argv/parser aliases after it has projected
the needed values into its own HIA state. Before requesting a later file it
must make the requested resume target slot vacant. RESUME may fill only the
target(s) explicitly requested by the last yield, checked as transport identity;
the service validates the full semantic request/response relation itself.
The last operation-18 argument 5 supplies a complete resumeSlotMask. A RESUME
must install exactly this set of child targets, not a subset: check every target
is below 64 before bit operations; reject bits 0..3, duplicate targets, occupied
targets, and more than four rows. The concrete service determines its slots in
HIA and binds them in its yielded packet. All rows are checked before installing
any alias. Lifecycle 1 requires a zero mask. Lifecycle 0 may use a zero mask
for a transport-only continuation, but no extra row may then be supplied.

A borrowed slot is distinguishable from an owned mapping. It is never made
writable, resized, munmapped, or used as an OS destination. Releasing a borrowed
descriptor only clears the child alias. The parent sources remain pinned for
the entire active service lifetime, including suspension, even if the child
has dropped an alias; this deliberately simple lifetime rule avoids premature
release while deeper existing program contexts can still refer to a source.
Parent GROW/RELEASE or RO->RW on any pinned source is rejected. New query or
response reads therefore use fresh parent file-owner work and payload slots;
the original program buffer cannot be reused.

Zero-length read-only views remain legal. Their logical capacity is zero while
their private mapping, if needed by the implementation, remains safely owned.
No host code substitutes an empty-input language error.

## Initial HIA command

The initial 128-byte HIACBI01 command consists of sixteen u64s:

magic, 1, serviceID, serviceLease, parentLease, parentSequence, action,
integerDigits, programBytes, argvBytes, parserBytes, 16, 1024, 32, 0, 0.

The final fields bind the existing parser inventory of sixteen 32-byte rows
starting at offset 1024. A row remains
[definedForAction, owner, offset, bytes], with owner 0 absent, owner 1 argv and
owner 2 parser literals. Empty supplied strings remain distinct from absence.
The HIA service verifies all spans against the actual installed read-only
slots. Header equality is not external authentication: the fixed private
issuer and immutable mappings are required.

integerDigits is a HIA-derived startup policy, never a number guessed by the
executor. The current seven-image capture only proved the tested UTF-8 startup
profile with the original 4300 digit policy. Full PYTHONINTMAXSTRDIGITS parsing
and its pre-argv startup errors are a separate open owner, not silently closed
by this ABI field.

## Child yield and resume

A new mechanical child event uses the same 128-byte HIACDE01 envelope with
operation 18. Only the selected service root may emit it; the actual allowed
root role is bound by the compiled table, not trusted from a payload.

Arguments are:
[serviceLease, lifecycle, childViewSlot, childViewOffset, childViewBytes,
 resumeSlotMask, 0, 0, 0, 0, 0, 0]

lifecycle 0 suspends with an expected resume; lifecycle 1 is a final service
result. The executor returns the actual child lease, sequence, calling role,
lifecycle and copied read-only target capacity to the parent in a typed
operation-17 ACK extension. It does not interpret the child view. All reserved
words are checked. Any BAD/ABI result destroys the service lease and rejects
the parent operation; no old frame or partial semantic result is published.

The complete yielded view is self-contained. Its HIACBE01 header is sixteen
u64 words (128 bytes), followed by the exact payload:

| Word | Meaning |
| --- | --- |
| 0..3 | HIACBE01, version 1, service ID, service lease |
| 4..6 | actual child yield sequence, logical request, kind |
| 7..8 | numeric exception domain, CLI exit |
| 9..11 | CLI field index, policy/format, child resume target slot |
| 12..15 | payload offset, payload bytes, total packet bytes, zero |

The HIA parent validates sequence against the executor's actual ACK and then
distinguishes these exact kinds; the executor does not interpret the packet:

1. NEED_FILE: domain/exit are zero; field is an existing declared CLI field;
   policy is its exact old read_bounded limit; target is the requested vacant
   child input slot. There is no payload (offset/bytes zero, total 128).
2. NEED_PUBLICATION: domain/exit are zero; field is output field 2; policy is
   1 actual program canonical bytes, 2 complete query compact JSON, or 3 exact
   assembly UTF-8 text. The requested vacant target receives the later actual
   publication receipt. The payload is the complete requested content;
   publication context stays in the child HIA state.
3. DONE: domain/field/target/logical-request are zero; CLI exit is 0 or 1 as
   selected by the business HIA; format is 1 compact JSON or 2 raw text.
4. ERROR: field/policy/target/logical-request are zero; exit is exactly 2;
   domain is 1 ValueError family, 2 OSError, 3 UnicodeError, or 4
   SubprocessError. Payload is the complete original str(error), encoded in
   the declared private text representation. HIAEditRejected and
   HIAProgramRejected use the ValueError family here, retaining their complete
   text. This transport does not invent an exception for an unsupported owner.

Nonempty payloads start at 128 and totalBytes == 128 + payloadBytes. A zero
payload has offset zero and total 128. All irrelevant fields must be zero.
For NEED kinds logical request is nonzero and increases exactly once per
request. NEED_FILE/PUBLICATION use child lifecycle 0; DONE/ERROR use lifecycle 1.
The parent validates the original action's allowed field/order/policy in HIA;
no generic kind permits reading an earlier or different CLI file.

The 128-byte HIACBR01 RESUME command has sixteen u64s:

HIACBR01, 1, serviceID, serviceLease, previousChildSequence, logicalRequest,
replyKind, parentSequence, fieldIndex, targetSlot, actualInputBytes,
matchingPolicyOrFormat, 0, 0, 0, 0.

replyKind is 1 FILE or 2 PUBLICATION and must match the actual last request.
The single new immutable input lease targets the requested vacant slot. The
carrier copies this command unchanged into the child's operation-18 ACK as
128 observed bytes; the child validates all semantic associations. The base
ACK uses the unchanged 64-byte HIA continuation envelope and actual child
lease/sequence. Inputs stay immutable until consumed; sequence and request
identity cannot advance on a GROW retry. A failed parent read/publication
retires the suspended child before rendering the original CLI E_DRIVER
result; no semantic operation is automatically replayed.

The parent operation-17 ACK likewise has the original 64-byte envelope with
return zero and observed length 128. Its sixteen-word mechanical extension is:

HIACBA01, 1, serviceID, serviceLease, actualChildLease, actualChildSequence,
actualCallingRole, lifecycle, parentTargetSlot, copiedViewBytes, verb,
actualParentSequence, 0, 0, 0, 0.

The root calling role and lease are read from the actual context, never a
semantic payload. The parent HIA updates only that actual target capacity and
then inspects the self-contained HIACBE01 view. RETIRE returns only the original 64-byte ACK with return 0, observed length 0,
and all reserved words zero. It produces no HIACBA01 extension or new view. Its
operation frame already binds the active service identity and last yield sequence;
the parent HIA does not infer a new completed service result from retirement.

These numeric layouts are fixed for the first implementation. The accompanying
assembly source is new and unexecuted; source storage and static checks do not
prove an executable or native result. The external edge uses SERVICE_HOST rather
than the old PARENT field, so the service root retains KIND=2, DEPTH=0, PARENT=0.
The original service→program→ordinary op_run_child/child_complete code remains
exact after deterministic label-prefix substitution. Internal children cannot
emit operation 18, create another CLI service, or enter a different role table.

## Required output order and compatibility boundaries

The ordinary CLI verifies the input program before reading query/response/
selections/request files. The service must yield only at that original point;
all later file errors must therefore follow successful actual admission.
For edit application, query reads precede response reads, and the original
single/batch limits remain separate.

stdout output_json uses ensure_ascii=False, indent=2, sort_keys=True, then LF,
without the worker's 8 MiB output quota. JSON publication uses ensure_ascii=True,
indent=2, sort_keys=True, allow_nan=False, then LF. Program publication uses
actual verified canonical bytes. Assembly publication uses its exact UTF-8
text. A publication receipt is not permission to skip the original program
admission and pathname/inode/exact-byte readbacks.

The already delivered compact Graph CLI pair is restricted to admitted
program/metadata graphs and still rejects lone surrogates. Actual OS output
paths can contain surrogateescape characters: original CPython stdout converts
DC80..DCFF back to raw bytes, whereas the private pretty component currently
emits UTF-8/surrogatepass. Full stdout encoding for path-containing receipts
therefore remains a distinct required owner. This draft does not reuse the
narrow graph/pretty result as proof for those paths.

## Narrow implementation and verification plan

1. Import the exact restored service executor/role map and add bounded context
   suspend/resume support in a new fork; retain the original bytes/pins.
2. First use an actual HIA test service to exercise BEGIN, one NEED_FILE yield,
   exact RESUME, DONE and RETIRE. Compare full frames, all bytes, actual syscall
   counts and mapping lifetime, with no Python interpreting the service packet.
3. The existing entry harness defines 193/176/17 intended cases; the latest
   actual build still failed before those cases ran. New context controls are
   separate counts and cannot supply or inherit those not-yet-observed results. Prove two service calls cannot be
   active, wrong seq/lease/role/spans never call the peer, and input canaries/
   physical RO remain intact through GROW and suspension.
4. Hold returned result views while retiring the child and verify bytes remain
   exact; reject attempts to mutate/release pinned parent sources. Exercise
   logical zero extents and the existing service->program->ordinary bound.
5. Bind actual parent-owned A/E service images and compare complete ordinary
   CLI stdout/stderr/exit plus file effects, including admission-before-read
   ordering. No assembly/build/legacy patch/impact closure follows from A/E.
6. Implement publication staging and final stdout encoding as complete
   separately tested HIA owners before changing installed dispatch.

All cases use original compiler and semantic resource limits. Development
context tests do not confer matching-source cold qualification or authorize
deleting any old production owner.
