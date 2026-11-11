# Reconstructed constructor continuation controller contract

Revision: RECONSTRUCTED-DESIGN-20261111-r1.
This text is reconstructed from retained conversation context after the local workspace changed. It is not the original Stage12 source or documentation and does not inherit its source hash, test identity, or qualification. It specifies the contract to reimplement and independently revalidate. The preceding Stage12 original archive is currently inaccessible and was not confirmed remotely saved.

## Scope and original observations

The previous development controller accepted an already issued, bounded document SourceIndexLease and drove every constructor continuation through actual HIA owners. It did not implement raw JSON admission, function lowering, outer lowering, final Core admission, or complete native normalization. All execution remained explicitly DEVELOPMENT under a retained direct x86 compiler.

Previously observed production identities (not recovered bytes):

| Item | Bytes | SHA256 |
|---|---:|---|
| tools/generate_hia_composite_constructor_driver.py | 39605 | 02085618c412dc1d180904ec6cec15deadafd589187ca3b8da988e3988ec3fe0 |
| docs/HIA_COMPOSITE_CONSTRUCTOR_DRIVER.md | 9254 | ed5f4376fc15da359a6442e0a9284122986660ccd3cb18f88ded2b15645d2056 |
| examples/hia_bootstrap/composite_constructor_driver.hiaasm | 168369 | 8ece1c2905a3de43159ef72688c5caf0d68b1c199cb4707828c6f3a3e4c72b43 |

Previously observed constructor controller shape: 40 functions, 740 blocks, 2873 instructions, maximum 72 blocks per function and 15 block parameters. These are historical author observations, not measurements of this reconstruction.

Previous controller image: 245910 bytes, SHA256 6e9ff0e6d99d6f402a97f5ab01be7c349a43369c1c48e1292f00756b0d04c695.
Previous constructor owner image: 163813 bytes, SHA256 b2ba27931954815f5e89efca0a7bbcd43afabd3dbd71b295cc0379edd659273d.
Previous constructor renderer image: 28278 bytes, SHA256 b392351ea2cbe4bbe1e534179bde8f94e227df882a23cec6c82c2b2a5b170539.

The preceding development compiler was 668608 bytes with SHA256 0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8. Its development compilation limits were 10 CPU seconds, 20 wall seconds, 256 MiB address space, 8 MiB stack, and the original 1 MiB compiler output/workspaces. Current matching source/compiler custody must be established anew before another compile.

## Private capabilities and input

The fixed executor owns nonoverlapping buffer mappings. It issues the original source packet plus the exact bitmap returned by the native typed-packet JSON validator as a read-only SourceIndexLease. Lengths, offsets, and identifiers do not authenticate arbitrary external arenas. The controller may trust only the fixed pipeline's actual leases and exact pinned images.

SourceIndexLease is eight little-endian u64 words:
[HIASIL01, packetBytes, ceil(packetBytes/8), 64, align8(64+packetBytes), totalExtent, 0, 0],
followed by the complete typed packet, zero alignment, and the actual native node-start bitmap. The packet's private ABI limit is 64 MiB. This is not a limit on expanded Core output.

The controller uses the existing outer RWW ABI: command read buffer, response write buffer of at least 128 bytes, and a mutable coordinator workspace of at least 65536 bytes. Its delegated images can use a second read-only input; those roles are explicit rather than inferred from pointer equality.

INIT is exactly 64 bytes:
[HIACDI01, lease>0, sourceLeaseExtent, legacy(0 or 1), 0, 0, 0, 0].
sourceLeaseExtent is 82..75497536 under the private source-lease ABI.
Pool slot 1 already contains that immutable source lease, slot 2 is the controller workspace, and unallocated pool slots have capacity zero.

## Event / acknowledgement protocol

A controller event is 128 bytes / 16 u64 words:
[HIACDE01, opcode, lease, operationSequence, arg0, ..., arg11].

There is one pending operation at a time. The sequence is monotonically increasing with no wrap. There is no additional language-level command quota.

| Opcode | Operation | Arguments |
|---:|---|---|
| 1 | CALL | imageID, firstSlot, firstOffset, firstExtent, secondSlot, secondExtent, workSlot, workExtent, observeSlot, observeOffset, observeExtent, 0 |
| 2 | GROW | slot, newLogicalExtent, then zeros |
| 3 | ZERO | slot, offset, size, then zeros |
| 4 | COPY | sourceSlot, sourceOffset, targetSlot, targetOffset, size, then zeros |
| 5 | RELEASE | slot, then zeros |
| 6 | PROTECT_RO | slot, 1, then zeros |
| 7 | HANDOFF | constructor result, described below |
| 9 | REFUSAL | transport refusal, with BAD return taking precedence |

The fixed executor does not parse types or service objects. It executes the requested bounded operation, preserving bytes during GROW and zeroing newly allocated bytes. It enforces exact issued buffer capacities, disjoint mutable and borrowed regions, and actual read-only mappings. Allocation and OS errors are transport failures; they are not silently converted into semantic language errors.

ACK is exactly 64 bytes plus the requested observation:
[HIACDA01, lease, operationSequence, opcode, executorStatus(0), actualImageReturn, observationBytes, 0],
then exactly observationBytes. Non-CALL operations require return=0 and observationBytes=0. CALL observations are bounded by 128 bytes in this constructor ABI.

Wrong magic, sequence, operation, status, extent, or state permanently refuses a full-size coordinator workspace. An undersized workspace may be unable to store poison; the final executor must discard the entire lease after every BAD return. It must never trust a stale event following BAD.

## Fixed images

1 owner packet projector;
2 typed packet to ordered JSON / node bitmap;
3 constructor semantic owner;
4 constructor renderer;
5 ObjectToken to source-reference IR;
6 type request projector;
7 type transport commands;
8 actual composite type semantic owner;
9 type transport reply validator;
10 type response framer.

The controller does not substitute BEGIN acknowledgement for an actual type result. BEGIN and init REPLY can have identical numeric fields, so provenance is the actual fixed call path and immutable leases.

## Buffer roles

| Slot | Contents |
|---:|---|
| 0 | Empty buffer, capacity 1 |
| 1 | Original SourceIndexLease |
| 2 | Coordinator workspace |
| 4 | Owner packet projector workspace |
| 5 | Constructor typed packet |
| 6 | Constructor SourceIndexLease |
| 7 | Typed packet JSON output |
| 8 | Typed packet JSON workspace |
| 9 | Constructor owner workspace, 192 MiB |
| 10 | Constructor owner output, 64 KiB |
| 11 | Source-reference IR workspace, GROW from 131328 |
| 12 | Type request projector workspace |
| 13 | Complete type BEGIN / REPLY immutable wire |
| 14 | Type transport workspace, GROW from 4096 |
| 15 | Actual type transport event, 128 bytes |
| 16 | Actual type semantic workspace, 128 MiB |
| 17 | Actual type output, 64 MiB |
| 18 | Type response framer workspace |
| 20 | Complete function initial typed packet |
| 21 | Complete outer initial typed packet |
| 22 | Function SourceIndexLease |
| 23 | Outer SourceIndexLease |

Image second-read roles 1, 5, 6, and 10 require immutable source / issued validator leases. Actual mutable type state remains a deliberately borrowed semantic workspace for kernels that require it; the fixed executor must not misclassify this as external immutable source authentication.

## Coordinator state offsets

All offsets below are u64 positions in slot 2.

0 magic; 8 status; 16 lease; 24 operation sequence; 32 phase; 40 pending operation; 48 continuation phase; 56 actual image return; 64 expected observation bytes; 72 allocation slot; 80 allocation bytes; 88 source extent; 96 legacy; 104 constructor stage; 112 profile; 120 constructor request; 128 wait state; 136 issued phase; 144 kind; 152 terminal error; 160 delegated error; 168 types live; 176 stream; 184 stream action; 192 producer sequence; 200 IR event sequence; 208 last final; 216 producer frame extent; 224 IR root; 232 IR node count; 240 IR extent; 248 owner target; 256 packet slot; 264 packet offset; 272 packet bytes; 280 JSON return phase; 288 JSON bytes; 296 bitmap offset; 304 bitmap bytes; 312 lease target; 320 lease return phase; 328 lease bytes; 336 constructor packet bytes; 344 constructor source bytes; 352 type operation; 360 type command sequence; 368 type error; 376 wire bytes; 384 response offset; 392 response bytes; 400 function packet bytes; 408 outer packet bytes; 416 function source bytes; 424 outer source bytes; 432 packet destination; 440 packet return; 448 metadata; 456 error group; 464 final error; 472 refusal reason.

Observation scratch is [512,640), argument scratch [1024,1120), packet header scratch [2048,2176), and capacity table at 4096+8*slot. A subsequent full lowering controller must use disjoint extension offsets and retain the already committed constructor/type state.

## Native constructor sequence

1. Project original source to the complete constructor packet [document, legacy].
2. Run the actual typed-packet JSON validator and form the SourceIndexLease from its actual bitmap, without a Python object decoder.
3. Allocate the constructor owner and output, and call the actual semantic image.
4. Check exact constructor frame phase, stage, profile, request and error correlation in HIA.
5. Consume each whole original renderer frame into the native source-reference IR. If IR grows, preserve and replay only its CONT command / same already produced frame. Do not re-enter the semantic producer or render a second version.
6. For each service, run native type-request projection; serialize its complete typed command with native packet JSON; run type BEGIN; call the actual type owner once; run type REPLY; frame the complete constructor continuation; call the actual constructor owner.
7. On a failed type initialization, produce the exact response before releasing slots 16, 17 and 14, and release those before returning the response to the constructor. This preserves original partial constructor state while preventing a failed factory from retaining the type session.
8. Ordinary later type semantic errors preserve already issued descriptors, counters and cache changes. They are not transport poison.
9. On terminal metadata, fully consume its native stream before releasing constructor workspace slot 9. The release acknowledgement precedes post-constructor packet projection.
10. On success, generate complete function and outer initial packets and source leases, retaining source-reference identity. Do not parse or validate function bodies ahead of their original lowering phase.

Constructor phases/kinds:
- phase 10, kind 1: type initialization, stage 1 request / stage 2 response;
- phase 30, kind 2: parameters;
- phases 41 and 81, kind 3: resolve;
- phase 50, kind 4: return origins;
- phase 82, kind 5: task protocol;
- terminal phase 2000, action 2, kind 0.
The latter service phases operate at stage 3. Constructor errors are 0..14 or delegated 999.

The terminal native metadata is [stage, profile, legacy, documentRef, registry4, origins].
registry4 contains [name, orderedParameters, orderedReturnIDs, originalFunctionRef].
The function packet is [document, registry3, origins, 0, 0, legacy, 0].
The outer packet is [document, registry3, 0, 0, [], []].
registry3 removes only the original function reference. The HIA projector preserves all ordering and full parameter/return data.

HANDOFF is:
[HIACDE01, 7, lease, lastOperationSequence,
 errorGroup, errorNumber, stage, profile, lastConstructorRequest,
 11, IRroot, IRextent, typesLive, functionPacketBytes, outerPacketBytes, 0].
errorGroup=0 success, 1 constructor semantic error, 2 delegated type error. Remaining buffers belong to the final fixed executor and must be closed on every public termination path. The constructor workspace has already been released.

## Exact packet JSON workspace arithmetic

For a complete typed packet of size S:
- tableSlots starts at 2 and doubles while tableSlots < 2*(S >> 5);
- bitmapBase = 128 + 16*tableSlots;
- bitmapBytes = ceil(S/8);
- stackBase = align8(bitmapBase + bitmapBytes);
- totalWorkspace = stackBase + 32*(floor(S/24)+1);
- output capacity = 64 + 6*S.

The exact reciprocal floor(S/24) = (S*2863311531)>>36 is valid within S<=64 MiB. The derived maximum workspace is 164976096 bytes. This private packet representation limit does not constrain expanded Core streams.

## Revalidation obligations

A reconstructed implementation must independently establish:
- public profile v1..v4 and legacy behavior;
- all five constructor services and exact complete state / alias semantics;
- returns resolution before stored-loan gates, return origins before effects, declaration-order unused task checks;
- failed initialization release order;
- exact real type commands / responses and entire committed type arena;
- exact complete function and outer packets;
- forged acknowledgements, component observations, persistent refusal, and held-error memory release;
- maximum existing returns / parameters / functions boundaries without added quotas.

Historical Stage12 reported 26 semantic cases and 17 protocol controls across 8 passing test methods, plus a separately retained first smoke assertion failure. The old 4096-return, 2048-parameter, and 1024-function runs were reported passing under their original limits. These reports are not execution evidence for this reconstructed revision and must not be relabeled as new tests.
