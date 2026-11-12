# Native checked machine plan: five-image development component

Status: **NEW / UNEXECUTED**. This revision has not been parsed by CPython,
generated, compiled by B3, run in the VM, or entered as native code. The Git
readbacks prove source identity only. No previous GraphWire, Function, Emitter,
Core, CLI, installed, or cold qualification is inherited by this component.

The original contract is exact 0ef hepta/hia_machine_plan.py,
Git 61833e8bf8497089461bad9eb2347c82a233e8b2, SHA256
ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a.
Its Core decoder is exact hepta/hia_program.py,
Git 5d0027f4453759e4156a3496e64215c441a727e4, SHA256
76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92.

## Scope and order

A fixed HIA controller performs the complete plan value path:

1. An exact-dict check, then the original bounded detached-snapshot acceptance
   rules, starting at the plan root at depth zero. Dict keys consume no nodes.
   Values are visited in insertion order. The active path detects cycles;
   repeated containers outside that path are allowed and counted again.
2. The two actual bounded GraphWire images run on the same immutable Graph and
   plan root, with flags 2 (sort keys, ensure_ascii=False), maximum 8,388,608
   bytes, and the actual integer digit limit. Their complete canonical UTF-8
   plan bytes are copied to a new readonly slot.
3. The semantic HIA image checks schema, exact keys, Core hash, block layout,
   function order, scratch bijection, instruction choices, alignment, scalar
   select, and value-register assignments in the original order.
4. The controller checks the actual semantic result descriptor, protects its
   workspace readonly, and publishes a descriptor retaining both the original
   Graph lease and the complete canonical plan.

The snapshot admits only exact null/bool/int/str/list/dict kinds. It rejects
float values, tuples, bytes, unsupported/subclass nodes, non-exact-string keys,
active cycles, depth greater than 64, more than 262,144 visited values, and the
original queued-node limit. These are the same supported value kinds as the
original Core object's snapshot. The subsequent generic GraphWire supports
more kinds, but is reached only after the strict plan snapshot succeeds.

Core _decode wraps its snapshot, structure, integer-conversion, Unicode, and
canonical-decode errors in the same plan error. This component preserves that
complete exposed error text. Internal Core exception-chain objects and Python
tracebacks are not native outputs. After the successful snapshot, GraphWire's
complete bounded canonical operation supplies the remaining scalar/byte gate;
only after that operation does any plan schema or choice check run.

The Graph contains both Core and plan, but their enclosing private list does
not count toward the plan's snapshot depth or node budget. Graph header totals
are transport extents, not public admission quotas. Plan traversal starts at
the exact second child. The whole Core side may contain many other reachable
nodes and is not recounted as part of plan admission.

## Authority and incomplete joins

The caller must issue an immutable Graph containing the **actual already
admitted canonical Core**, and bind its SHA256 to the request. The private
carrier must retain the same actual mappings, descriptor capabilities, command,
workspaces, image entries, and ACK sequence. A matching Graph header, hash field,
event, nominal VerifiedProgram object, or result magic does not establish
public input authority.

The new test corpus obtains its Core fixture from the original exact Python
reference before entering native code. It is not a test of a native Core
admission producer. A full public entry must connect the actual native Core
producer and native generic object capture/issuer to this controller; that join
remains open. The Python mechanical Graph capture in these tests freezes exact
tags, alias/cycle edges, raw integer magnitudes and surrogatepass strings. It
does not admit a plan, serialize its output, or feed an expected semantic ACK.

The semantic image alone is not a public plan API. Its correct result requires
the preceding strict snapshot and actual complete canonical-wire operation.
This ordering is owned by image 5.

The independent value checker establishes the same closed-block register
acceptance as register_assignment_witness. It does not yet export that
function's full witness JSON or the preservation_checks report. The success
descriptor retains everything needed for a later HIA report owner. This
component does not emit code, allocate registers, select an optimization,
publish a preservation theorem, replace the actual Emitter, or qualify the
public build/installed command.

## Five fixed images

| Role | Entry | Operand rights | Function |
|---:|---|---|---|
| 1 | plan_snapshot_gate | R / R / W | exact root and bounded snapshot |
| 2 | original GraphWire scan | R / R / W | complete original graph/string/key checks |
| 3 | original GraphWire emit | R / R / W | complete canonical bytes and digit/size gate |
| 4 | plan_semantics | R / R / W | schema, choices, layouts and inclusive lifetimes |
| 5 | plan_controller | R / W / W | actual command/ACK continuation |

Roles 2 and 3 are freshly compiled from complete published HIA source. There is
no host serializer in the path and no reuse of an old compiled image result.
Their precise sources under the restored workspace are:

| Role | Path relative to workspace | Bytes | SHA256 |
|---:|---|---:|---|
| 2 | native-edit-candidate-next/development/build-r1/source/59/graph_json_wire_scan.hiaasm | 147822 | c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3 |
| 3 | native-edit-candidate-next/development/build-r1/source/61/graph_json_wire_emit.hiaasm | 173680 | 9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2 |

The original GraphWire common is Git 0711ccf18b3838e53b47821c464c3492b802eff6,
13815 bytes / SHA256 32ceeceb285f9d3d3250a920c40ebd7bac8e1a44460c5321d714f6f5a0da2b3c.
It documents flags 0..3. No CLI sentinel or unbounded-output policy is used here.

## Pure image input

First operand is the entire immutable HIAGRF01 GraphLease. Its root is an exact
two-element list [admittedCore, submittedPlan]. Node IDs are one-based; scalar
offsets are absolute Graph offsets; minimal LE integer magnitudes and actual
string character counts follow the unchanged Graph ABI. Empty integer payloads
still have a valid scalar-pool cursor. No descriptor is treated as an issuer.

Second operand is exactly 128 bytes, HIAMPC01 version 1:

| Qword | Value |
|---:|---|
| 0 | HIAMPC01 |
| 1 | 1 |
| 2 | nonzero Graph lease |
| 3 | nonzero logical request |
| 4 | exact Graph root ID |
| 5 | exact full Graph byte length |
| 6 | mode: 0 snapshot, 1 semantics |
| 7 | zero |
| 8..11 | 32 raw Core SHA256 bytes |
| 12..15 | zero |

Third operand is a private mutable workspace of at least 32768 bytes. Pure
entries clear their fixed scratch and recompute from the same immutable inputs.
A workspace below this minimum returns BAD. A larger dynamic scratch need emits
GROW; the caller preserves both immutable inputs and retries the same pure
entry after growth. Pure entries do not offer persistent poisoning between
independent requests; image 5 owns permanent rejection of a corrupted session.

## Pure event and result

The first 128 workspace bytes are HIAMPE01:

| Qword | Value |
|---:|---|
| 0..1 | HIAMPE01, version 1 |
| 2 | action: 0 success, 1 GROW, 2 semantic error, 3 BAD |
| 3..5 | Graph lease, logical request, mode |
| 6 | semantic error ID, otherwise zero |
| 7 | complete required workspace bytes |
| 8..9 | result/error offset and bytes; zero for no view |
| 10 | recognized schema version 0..4 |
| 11 | snapshot visited count; semantic image always zero |
| 12..13 | plan ID, Core ID |
| 14 | phase: 1 snapshot; 2 schema/hash; 3 layouts/choices; 4 assignments; 5 complete |
| 15 | private BAD reason, otherwise zero |

Success or semantic error returns 128, GROW returns 0xfffffffe, private BAD
returns 0xfffffffd. A successful snapshot has no payload. Semantic success
publishes HIAMPR01 at workspace offset 1024, exactly 128 bytes:

Qwords 0..7 are [HIAMPR01,1,GraphLease,request,CoreID,planID,version,GraphBytes].
Bytes 64..95 contain the exact Core digest; bytes 96..127 are zero.

Semantic errors carry the complete original UTF-8 message at offset 20480.
The 4096-byte error area is an implementation bound derived from the original
128-character ASCII Core identifier limits and the fixed error formats, not a
new user-message truncation policy. No error text is truncated.

Schema and error ordering exactly follow the reference:

| ID | Original message after E_HIA_MACHINE_PLAN: |
|---:|---|
| 1 | plan must be an object |
| 2 | plan requires bounded plain JSON data |
| 3 | unknown plan schema |
| 4 | plan has missing or unreviewed fields |
| 5 | plan belongs to a different Core |
| 6 | invalid block order map |
| 7 | unknown function in block order |
| 8 | block order must name every member exactly once |
| 9 | function order must name every member exactly once |
| 10 | scratch assignment must bijectively rename only r10 and r11 |
| 11 | instruction choices must be explicit and complete |
| 12 | unreviewed immediate move encoding |
| 13 | unreviewed immediate arithmetic encoding |
| 14 | unreviewed function alignment |
| 15 | unreviewed scalar select encoding |
| 16 | value_registers must be a function map |
| 17 | unknown function in value register assignment |
| 18 | value registers must be explicit assignments admitted by this plan version |
| 19 | caller-clobbered value registers require a leaf opcode whitelist; no calls, swap or allocation/bulk helpers |
| 20 | leaf registers require scalar/borrowed parameters and scalar returns |
| 21 | register assignment requires an existing integer or boolean SSA value |
| 22 | interfering values FN/BLOCK: LEFT and RIGHT share REGISTER |

After canonical decode, dict traversal is in Unicode key order. Valid scalar
UTF-8 byte order has that same order. The semantic checker therefore visits
map entries in increasing byte order independently of their original Graph
insertion order. All function-name keys in value_registers are validated
before any per-function mapping. Leaf opcode rejection precedes parameter/
return-type rejection; both precede definition membership and interval checks.

Intervals use the unchanged admitted Core block order. Parameters start at
zero, operation results at their one-based operation position, and even dead
results occupy that definition point. Inputs extend to each actual use;
terminal arguments extend to ops+1. Register order is rbx,r12,r13,r14,r15,
followed by r8,r9 only for v4. Rows sort by (register, first, valueName).
The first adjacent pair with left.last >= right.first produces the complete
reference error. Target block layout does not reorder this validation.

Definition records, a checked open-addressed hash table, block ranges, and a
heapsorted pointer vector are allocated by exact required sizes. GROW preserves
the original semantic order by recomputing, and never commits partial success.

## Controller input and fixed slots

The first request is readonly HIAMPB01 (128-byte header) followed by the complete
Graph. Qwords 0..7 are [HIAMPB01,1,controllerLease,request,GraphLease,rootID,
GraphBytes,integerDigits]. Bytes 64..95 are the actual Core SHA; the remaining
32 header bytes are zero. All three identities are nonzero; the Graph root,
header, extents, exact list shape and child IDs are checked before using them.
Integer digits zero means the original disabled limit; ordinary CPython
nonzero limits come from the actual caller configuration.

Image 5 uses a mutable 128-byte output and private 1 MiB workspace. It uses
the unchanged HIACDE01 / HIACDA01 mechanical protocol from exact common
e56539a9cb76f95010ea6ca995737f40ab6e1850:

| Operation | Mechanics |
|---:|---|
| 1 | actual image CALL with checked operand and observed-view extents |
| 2 | GROW and complete prior-byte copy |
| 3 | ZERO a checked writable span |
| 4 | COPY exact actual bytes |
| 5 | RELEASE an owned slot |
| 6 | PROTECT actual mapping rights |
| 14 | VIEW at most 256 actual bytes for the next ACK |
| 7 | terminal, no further ACK permitted |

Slots are fixed:

| Slot | Ownership |
|---:|---|
| 0 | empty readonly |
| 1 | immutable initial header and complete source Graph |
| 2 | private controller state |
| 3 | actual 128-byte mechanical event |
| 4 | HIA-produced readonly peer command |
| 5 | snapshot workspace |
| 6 | actual shared GraphWire scan/emit workspace |
| 7 | semantic workspace, protected readonly before success |
| 8 | complete canonical plan, copied and protected readonly |
| 9 | complete success descriptor, copied and protected readonly |
| 10 | complete error text, copied and protected readonly |

The controller checks peer return values, mode, source IDs, logical request,
lease, phase, recognized schema, requested workspace growth, payload extents
and every defined zero field before advancing. Semantic GROW needs strictly
more current capacity and nondecreasing need/phase. GraphWire retains its own
persistent state and GROW resumes the actual selected image. A NEXT action is
accepted only from role2 and selects role3. An output COPY is range-checked
before issuing mechanics. The final HIAMPR01 is read from the actual workspace
through VIEW, checked including its raw Core digest, and only then protected
and published. Bad ACKs or session replies poison the controller permanently.

These checks protect the private state machine against erroneous internal
frames; they do not authenticate fabricated external Graph/peer messages.
Source and peer mappings must come from the fixed private issuer/carrier.

## Controller terminal

Success terminal is HIACDE01 with operation7, current lease/sequence, Q4=0,
Q5=0, Q6=9, Q7=0, Q8=256. Error has Q4=3, Q5=semantic error ID, Q6=10,
Q7=0, Q8=full text bytes. In both cases Q9..15 are request, Graph lease,
plan ID, Core ID, version, canonical bytes, snapshot visited count.

The success view is HIAMPD01, 256 bytes:

- Q0..7: magic,1,controllerLease,request,GraphLease,sourceSlot1,sourceOffset128,
  complete Graph bytes.
- Q8..15: CoreID,planID,version,canonicalSlot8,offset0,canonicalBytes,
  semanticSlot7,eventOffset0.
- Bytes128..159: actual Core digest.
- Q20..23: snapshot visited count, actual integer digits, flags2, maximum8MiB.
- Q24..31: zero.

Slots1,7,8,9 and their mappings stay live and readonly until the owning caller
finishes consuming the result. A caller must retain those real leases; copying
the 256-byte descriptor alone is insufficient. This revision does not hash the
canonical plan; a later actual native SHA owner must do so if the public outer
requires a plan hash.

## Build, tests and evidence

Each of five fresh builders runs with 90 CPU / 180 wall / 1 GiB and core dumps
disabled. The exact compiler is 669556-byte B3 with SHA256
35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b.
Every B3 child keeps 10 CPU / 20 wall / 256 MiB.

Every canonical HIA source, full document, generation profile, actual image,
compile receipt, authoring source and source-before/after inventory is retained.
The original bootstrap gates are functions<=128, blocks<=1536, ops<=8192,
max blocks/function<=256, max block params<=16, SSA suffix<2048. Maximum ops
per block is recorded without adding a new 128-ops/block gate.

The new schedule contains 55 independent groups and 679 cases, including
119 private controller controls. Each group keeps 90 CPU / 180 wall / 1 GiB.
Cases run the complete original Core/plan oracle first. During actual native
continuations the host Core/plan methods are replaced with functions that fail
if called. Ordinary mechanics only consume actual HIA commands and actual
image output; the test-only corruption hook is used solely by labelled private
controls.

Coverage includes all four plan schemas, all 192 reviewed choice combinations,
complete original error strings/first-error combinations, all 30 exact leaf
opcodes, returning-call restrictions, full 128-character identifier diagnostics,
resource/type restrictions, all seven register choices, inclusive
dead/input/output/terminal lifetime conflicts, backedge staging references,
canonical map order, alias/cycle/subclass/float/Unicode cases, disabled and
640/4300 digit limits, depth64, nodes262144/+1, wire8MiB/+1, huge integer
lower-bound rejection, 1024 functions, 4096 blocks and 8192 definitions.

Every actual entry saves all three complete logical operands before and after,
with hardware readonly protection and surrounding guard pages/canaries.
All commands, ACKs, 128-byte peer events, terminal views, canonical bytes and
original error bytes are retained. Lossless paged CAS checks each full memory
read, reconstructs the delta page list immediately and re-decompresses every
retained page at close. Final archive sealing streams every regular file and
mode/hash through tar+xz and checks the full streamed readback; it does not
discard unchanged intervals or use final-only evidence.

No predicted count is an observed result. The first actual build/test outcome,
including any source/profile/fixture failure, must be preserved separately.
