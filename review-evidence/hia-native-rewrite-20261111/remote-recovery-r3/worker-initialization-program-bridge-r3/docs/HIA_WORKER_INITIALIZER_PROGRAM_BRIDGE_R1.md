# Initializer P16/P17/P18 native program bridge

## Status and scope

This revision contains complete new source for the private initializer-to-program
bridge and its first independent CI gate. It has **zero new AST, generation, B3,
native-entry or ELF execution observations** at this checkpoint. Source text has
been persisted as Git blobs and read back in full. Earlier component results do
not qualify this composition.

The bridge replaces the constructor's P16 verification, P17 rendering and P18
assembly value peers. Two new HIA images own request interpretation, program
framing, receipt and error validation, retained program records, Core conversion,
registry import and initializer replies. The existing full syntax, renderer and
program-admission owners execute in a separate fixed native ELF. This uses the
complete assembly service; it does not substitute the bounded bootstrap parser.

The complete initializer still uses a Python mechanical development executor.
Eight initializer peer IDs, 1, 3, 4, 5, 6, 7, 13 and 14, remain explicit foreign
fixtures. Actual namespace put, SQL, file publication and transaction authority
remain open. A Graph ID and the private program record described here grant no
namespace authority.

Program diagnostics for rejection groups 1 through 6 and 9 remain open in the
inherited service. The bridge preserves the actual available full error frame;
it does not reconstruct a missing public message in Python. There is no default
selector, installed-entry activation, whole Worker claim or cold qualification.

## Source identity and predecessor failure

The fixed program dependency is source index
`ca7e78bcbdba6b2758a94e2ca1b564dd439da2c7`, with build helper
`50024531da0c93694c8de55dc817f4bafc9282c8`. This is the minimal namespace-package
import correction following FOLLOW40 job 131079272197. That original job failed
at `tools.__path__.insert` before attempting B3 or entering a native semantic
case. Its full log, original observations and all unrun groups are preserved in
delivery `cfdab1767fe65de5ad6eaae1acfc7c946d140ffb`.

The new composition does not reuse the failed builder. Its program role sources,
fixed executor, native packer, service test inventory and original limits are
otherwise unchanged. The first successful build and execution of that corrected
service remain to be observed.

The bridge imports exact retained initializer value/sequence, resource
front/result, Graph registry, Graph wire, decoder and complete DataGraph source.
The generator selects existing helper functions by AST identity and records the
full input file identities. It does not add Python runtime business logic.

## Private ownership and calling convention

Both new bridge images use first buffer R, second buffer R, third buffer W.
The assembly wrapper borrows the original second mutable parameter read-only
while invoking the owner. The first buffer is the current registry Graph. The
second contains a complete 128-byte command and its declared payload. The third
is one route's private growable workspace, shared between the input and output
images and never shared with another route.

The fixed executor must retain the same immutable Graph/input/callback leases
until consumed. Header comparisons correlate calls inside that invocation.
They do not authenticate an arbitrary replacement Graph, arena, receipt or
same-shaped foreign payload. Tests which mutate private frames are transport
controls, not public-source authenticity proofs.

Workspace growth preserves every prior byte and appends zeroed capacity.
GROW repeats the same copied callback, including its original command header;
it must not repeat the producer. A return of 0xfffffffd (BAD) retires the route
and all its outstanding views. An advertised workspace shorter than 8192 bytes
can return BAD without writing poison, so the caller must discard it even if an
old complete workspace is still available. A completed route cannot restart.

### Workspace layout

| Region | Byte interval | Purpose |
| --- | --- | --- |
| State | 1024 through 1519 | Offset-only route state |
| Event | 2048 through 2303 | Complete 32-word event |
| Registry command | 2304 through 2431 | Complete HIAWGC01 command |
| Graph wire command | 2432 through 2495 | Complete HIAGWC01 command |
| Saved callback header | 2560 through 2687 | Exact own-GROW retry header |
| Saved source header | 2688 through 2751 | Current Graph correlation |
| Prior registry/pure event | 2816 through 3071 | Issued predecessor correlation |
| Initializer event | 3072 through 3327 | Actual pending constructor event |
| DataGraph configuration | 3328 through 3455 | Complete private converter config |
| Decoder configuration | 3456 through 3519 | Original decoder node/depth config |
| Original Core digest | 3840 through 3871 | Actual initializer's 32 digest bytes |
| Initializer reply header | 4096 through 4351 | HIAWIR01 |
| Retained dynamic bytes | 8192 onward | Original input, actual frame, arena and packets |

Only the error terminal may extend the initializer reply after byte 4352.
That occurs after complete frame validation and terminal success of the route;
overlapping retained bytes are moved in the correct direction. Earlier state
and event regions remain disjoint.

## Command ABI

The command is 16 little-endian u64 words with magic HIAWPBC1. The complete
declared payload immediately follows it.

| Word | Meaning |
| --- | --- |
| 0 | HIAWPBC1 |
| 1 | Mode |
| 2 | Invocation ID |
| 3 | Call ID |
| 4 | Nonzero private route lease, at most u64 max minus 4 |
| 5 | Last consumed bridge event sequence |
| 6 | Current registry Graph lease |
| 7 | Complete current registry Graph extent |
| 8 | Payload extent, exactly second-buffer length minus 128 |
| 9 | Actual producer return or process return code |
| 10 | Actual producer role, or BEGIN initializer workspace extent |
| 11 | First returned extent |
| 12 | Extra extent or BEGIN prior-event extent |
| 13 | Extra field |
| 14, 15 | Zero |

The event sequence starts at zero in BEGIN. Ordinary callbacks must bind the
last event. Own-GROW replay is the sole exception: it retains the original
128-byte command header exactly and cannot introduce a new callback.

| Mode | Input image | Payload and correlation |
| --- | --- | --- |
| 1 BEGIN | Input | Actual full initializer workspace followed by the preceding 256-byte registry/pure event; word 9 = 2304, word 10 = initializer extent, word 11 = 768, word 12 = 256 |
| 2 BORROW | Input | Actual 256-byte registry event; return 768, role 1, extent 256 |
| 3 WIRE | Input | Complete actual Graph wire workspace; return 128, role 2 scan or 3 emit, exact workspace extent |
| 4 PROGRAM | Input | Actual stdout followed by actual stderr; return code 0 or 2, role 4, stdout and stderr extents |
| 5 RESERVE | Output | Actual complete registry reservation event; return 768, role 1, extent 256 |
| 6 DECODER | Output | Complete actual decoder output followed by complete scratch; actual native return is the arena extent, role 5, both capacities exact |
| 7 DATAGRAPH | Output | Complete actual DataGraph workspace; return 2240, role 6, exact extent |
| 8 IMPORT | Output | Actual complete registry imported-result event; first buffer is the newly issued complete registry Graph |

The input owner accepts only modes 1 through 4; the output owner only 5 through
8. The same route state selects which owner is currently allowed.

## Event ABI

Every ordinary event returns 2304 and is found at workspace offset 2048. It is
32 little-endian words with magic HIAWPBE1. BAD is authoritative even if the
event cannot be refreshed, including event-sequence exhaustion.

| Word | Meaning |
| --- | --- |
| 0 | HIAWPBE1 |
| 1 | Action |
| 2, 3 | Invocation and call |
| 4, 5 | Route lease and new event sequence |
| 6, 7 | Internal phase and refusal reason |
| 8, 9 | Original initializer pending sequence and peer |
| 10, 11 | Original source lease and integer digit profile |
| 12 | Required own workspace capacity |
| 13 | Requested fixed peer role |
| 14, 15 | Complete command offset and extent |
| 16, 17, 18 | Source owner, source offset, source extent |
| 19, 20 | Peer workspace and output requirements |
| 21 | Fresh peer-workspace flag |
| 22, 23 | Second source or imported packet offset and extent |
| 24, 25 | Registry event sequence and active registry command |
| 26, 27 | Current registry Graph lease and extent |
| 28, 29 | Complete initializer reply offset and extent |
| 30 | Next bridge kernel, 1 input or 2 output |
| 31 | Zero |

| Action | Required mechanical operation |
| --- | --- |
| 0 | Consume complete HIAWIR01 reply, then retire route |
| 1 | Grow this route, replay the same immutable callback |
| 2 | Forward the HIA-authored registry BORROW, RESERVE or IMPORT command |
| 3 | Call the selected Graph wire scan/emit image with its existing workspace |
| 4 | Run the exact source-bound fixed native program ELF |
| 5 | Call the exact raw data decoder using R/W/W |
| 6 | Call the exact complete DataGraph image using R/R/W |
| 7 | Refusal event; BAD always terminates the route |

Source owner 1 means the current private registry Graph; source owner 3 means
this route's workspace. Every view lasts only through the relevant immediate
call. After growth or a subsequent call, the caller must use the newly returned
offsets, never an old pointer.

## Original constructor order

BEGIN requires a real pending constructor event in phase 64, 65 or 66 and peer
16, 17 or 18 respectively. It binds invocation, call, pending sequence, origin,
digit profile, one argument, no extra argument/view/literal, and the entire
original 32-word initializer event. The route does not advance the initializer
until its final reply is ready.

For P16, BEGIN additionally requires the immediately preceding actual pure
P9 mode-4 event which produced the example document. An observational registry
BORROW is not allowed to replace that predecessor. The current Graph argument
must already be issued by the same registry.

For P17 and P18 the prior issued registry event is retained and validated. P17
must refer to the initializer's actual program handle; P18 to its actual assembly
handle. All serials and Graph generations are preserved through real registry
callbacks. The registry's RESERVE/IMPORT and actual Graph merge perform the
handle issuance; the host does not invent the returned handles.

### P16 verification

The HIA route borrows the example Graph root, runs the exact Graph wire scan and
emit pair, and sends its full resulting insertion-preserving object wire to the
program service. Flags are 0, the original maximum is 8 MiB, and the actual
configured digit profile is forwarded. This is the initializer's existing
integer/UTF-8 example domain, not a new arbitrary Python-object public capture.

The fixed program child performs actual schema selection, normalization and
full final Core admission. Its actual 256-byte HIAPRV01 receipt and complete
Core bytes are retained together with the exact original input. The output
bridge imports three native values: a private program record, the complete Core
Graph, and the lowercase 64-character Core digest derived from the receipt.
No digest is synthesized by the test driver.

### P17 full rendering and revalidation

The HIA route borrows the private program record and verifies its entire record
and program-frame/receipt structure. The receipt's Core digest must equal the
original initializer's stored 32 bytes.

For a primitive program it forwards the already canonical Core to the complete
render service. For a structured program it retains and forwards the original
structured input and its original object-wire flag. The complete render service
revalidates the input, performs its full assembly representability check, renders
the complete assembly, and performs the original assemble/verify roundtrip.
The returned Core digest must still match the original initializer.

The bridge imports both the full assembly string and its exact UTF-8 bytes.
The string's character count is computed in HIA. Both native Graph values remain
available to the constructor's subsequent put and assemble operations.

### P18 complete assembly

The route borrows the actual assembly string and passes its complete UTF-8 bytes
to the fixed assemble service. That service runs full syntax and ordinary
program verification, including the public assembly profile and limits.
The output bridge again imports the full private program record, Core Graph
and actual Core digest. The original initializer performs its final roundtrip
digest check and continues its original stores in their original order.

## Program process and complete result frames

The actual fixed child receives 64-byte HIAWPI01 followed by exactly the declared
input and EOF. Its fields are magic, private lease, request, digits, input extent,
mode, object-tree flag and zero. Modes are 1 verify, 2 render, 3 assemble.
The generic service also has mode 4 diagnose; this constructor bridge does not
add a diagnose peer.

On success, exit code is 0, stdout contains the complete HIAWPE01 frame, and
stderr contains exactly a 128-byte actual carrier terminal. On semantic
rejection, exit code is 2, stdout is empty, and stderr is the actual terminal
followed by the complete HIAWPE01 error frame.

The bridge validates the full terminal, frame magic/version/mode/lease/request,
all reserved fields, exact total and view extents, receipt owner identities,
source/core version relationship, canonical input/Core sizes, and full error
code/text framing. The actual receipt lease is the route lease plus 2.
It does not accept a successful BEGIN acknowledgment as a final receipt.

P16 accepts a program rejection domain. P17 can first fail program validation
or later assembly representation and therefore accepts the corresponding
program or assembly domain. P18's assembly domain retains syntax,
core-verification or representation phase and the actual line.

Error code and full message bytes are copied from the actual validated child
frame into HIAWIR01. The original initializer consumes that whole peer error
with its original unwind behavior. This does not close diagnostic groups for
which the inherited program service has no complete text.

## Private record and Core conversion

A program record is a native Graph kind-9 bytes value. Its 64-byte HIAWPC01
prefix is:

`[magic, 1, invocation, call, oldPending, originalInputBytes, inputTree, frameBytes]`

The exact original input then the entire successful program frame follow.
The record is private to this issued registry. It is not an external
VerifiedProgram capability, a checksum authenticator or a namespace receipt.

Core Graph conversion calls the exact HIADATA1 decoder on the actual admitted
canonical Core and then the complete DataGraph owner on that arena and the same
wire. The bridge derives the decoder's original capacities from Core extent,
keeping the node limit 262144 and depth limit 64. It copies the decoder's actual
arena extent, binds its actual output and scratch capacities and checks that the
node/depth configuration remains unchanged.

DataGraph starts with the exact 128-byte HIADGC01 configuration at offset 128.
Fields are magic, invocation, call, arena lease, wire lease, result Graph lease,
digits, actual arena extent, actual Core extent and seven zero words. The arena
and wire leases are route lease plus 1 and plus 2; the Graph lease is the actual
registry reservation. Config bytes 200 through 255 remain zero.

The actual DataGraph owner may request growth in its original phases 10 and 20.
The bridge preserves the same actual decoder arena and original Core. DataGraph
callbacks retain its full workspace, saved configuration and saved arena header.
Only its complete integer Core result is expected here; an unexpected binary64
continuation is rejected as a private protocol error. This does not replace the
separate complete general DataJSON owner.

Every import is checked against the complete resulting registry Graph. The
retained helper checks root/header/extent, all relocated nodes and exact scalar
bytes. The route then advances the actual registry generation and only then
returns handles to the constructor.

## Initializer replies

Success HIAWIR01 is 256 bytes. Peer 16 or 18 uses kind 11 with program-record,
Core-Graph and hex-digest handles, plus the actual 32-byte digest. Peer 17 uses
kind 12 with assembly-string and UTF-8-bytes handles.

A semantic error uses kind 0, error flag 1, actual route lease, and the complete
child error frame appended after the 256-byte header. Reply and appended frame
extents are exact. The original initializer's next event must refer to that same
actual error view; the development driver does not recreate an exception
message.

## Independent test and build plan

The CI gate restores exact reference and component sources, checks every
submitted Python file with AST before use, and retains all source/image/compiler
receipts before and after. The same original B3 image is required:
668608 bytes, SHA256
0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8.
There is no fallback to the different 35ee compiler.

Fresh builds are eight registry/initializer peers, two digest/SHA peers, one
Store value peer, two resource/metadata peers, four program bridge/decoder/
DataGraph peers and six fixed program/packer images: 23 compiler invocations.
The worker side has 17 live component roles. The program context has 41 live
roles in 63 table rows. These counts overlap retained implementations and are
not asserted to be 58 distinct images.

| New group | Cases | Actual program ELF processes | Required evidence |
| --- | ---: | ---: | --- |
| program-semantic | 3 | 9 | Full original constructor, complete Store method oracle, empty/Unicode/duplicate roots |
| program-failure | 3 | 6 | Exact partial attributes and original order after observer failures at verify/render/assemble |
| program-capacity | 2 | 6 | Complete exact and staged-growth constructors, identical full values, no repeated producer |
| program-protocol | 121 | 6 | One complete constructor, 117 actual-frame negative controls, three real private child rejections |
| Total planned | 129 | 27 | No inherited case or entry counts |

All reference business work occurs before the native interval. The reference
uses the complete original Service and Store methods and the complete original
program/assembly modules. During each actual route the old verify, assemble,
render, assembly parser and json.loads paths are disabled. Python transfers
only actual bytes, fixed event-directed calls, process lifecycle and evidence.
Post-route Graph decoding is observational and cannot feed the HIA route.

The three private child-rejection controls deliberately issue different private
inputs to cloned protocol contexts. They verify actual error-frame transport
and original initializer unwind. They do not claim the unchanged constructor's
public example is rejected, or claim that a same-shaped substituted source is
authenticated.

Every native call retains full before/after buffers, canaries and input equality
checks. Every fixed process retains complete stdin/stdout/stderr, actual process
status and lifecycle evidence. Completed-case ledgers and pending-entry records
remain separate so an incomplete group is never represented by its last
completed case.

Each original compiler invocation keeps 10 CPU seconds, 20 wall seconds and
256 MiB. Each complete test group keeps 90 CPU seconds, 180 wall seconds and
1 GiB. The CI additionally requires both the external complete-process-tree CPU
observation and the accounted process's cumulative self-plus-reaped-child CPU
to be below 90 seconds. Exit 0 alone is insufficient.

The HIA profile remains 128 functions, 1536 blocks, 8192 operations, 256 blocks
per function, 16 block parameters and SSA numeric suffix below 2048. No new
per-block operation quota is introduced. The workflow outer limit is 50 minutes
to contain independent groups and evidence sealing; it changes none of the
compiler or group limits.

The first new CI observation must record all generated profiles, actual compile
receipts, fixed ELF identities, actual native counts, process-tree CPU and full
failures. The original P12 91-case result, earlier initializer eight cases and
the standalone program-service 113-case inventory are not rerun or counted as
this bridge's results.
