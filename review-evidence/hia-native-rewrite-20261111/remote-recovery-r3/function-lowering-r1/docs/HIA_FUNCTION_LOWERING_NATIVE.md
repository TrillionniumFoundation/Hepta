# Native Function lowering and actual Code continuation, revision 1

## Status and exact scope

This is a new development component. At the time this source was frozen, the two
new owners and their new five-component chain had not been generated, compiled,
or executed. All counts in the proposed test schedule are planned counts.

The previously published Function frame planner and x64 encoder/finalizer have
their own completed evidence. Their success is not transferred to this revision.
This build regenerates and compiles those dependencies from their exact frozen
sources; it does not rerun either old test suite.

The runtime split is:

1. The existing native Function planner receives an actually admitted primitive
   Core and its actually checked machine plan, and produces the complete original
   stack/value/call/edge/result plan.
2. The new HIA tape owner reads the same immutable Core Graph plus the actual
   read-only planner workspace. HIA selects every original Code method, argument,
   label, serial boundary and block-budget observation.
3. The new HIA issuer consumes that actual tape and actual encoder replies. HIA
   writes the complete Code command Graph, waits for its actual reply, commits the
   original per-command serial/offset state, and decides continuation or failure.
4. The actual frozen HIA x64 encoder executes each native-produced command.
5. The actual frozen HIA finalizer resolves fixups and publishes complete machine
   bytes and relocations.

The development caller copies actual views and grows buffers. No Python-generated
instruction plan, expected argument, opcode selection or machine byte is fed back
to the HIA chain. The original Python classes are isolated comparison oracles.
Initial Code configuration and optional boundary seed are explicit test
preconditions; a production Emitter must own those choices in HIA.

This component does not perform Core admission, machine-plan validation, whole
Emitter profile checks, export selection, foreign entry wrappers, whole-program
text checks, ELF joining, shared linking, installed dispatch, or cold
qualification. Those remain separate owners. A successful private frame or tape
header does not authenticate arbitrary supplied bytes.

## Exact source identities

| Component | Git blob | SHA-256 |
| --- | --- | --- |
| Original hia_program_native.py | 1d0e0344f8300b11b5dd505cbea655170aba5be1 | bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c |
| Original hia_machine_plan.py | 61833e8bf8497089461bad9eb2347c82a233e8b2 | ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a |
| Original hia_machine_x64.py | 8e87bd317c5f61e00993bb0bf8d803c5385d6556 | 8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9 |
| Frozen native frame author | bb475cb50848f09dc4fda62ab1aa869bc0b9891d | 27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd |
| New native lowering tape author | d5b590bb7c67c34e9f994ff550da99358371a281 | e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb |
| New native Code issuer author | 0309b3f34843287552778eefda7962a7f95f4f02 | f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219 |
| Frozen native x64 author | 817443cde4a81402e850086b80ac5de985b62183 | 92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a |

The builder and CI freeze every executable authoring/reference dependency before
import and read all original inputs again at completion. The source manifest
contains the complete additional source, test-helper, runner and compiler pins.

## Common byte rules

All words are little-endian u64 unless explicitly stated otherwise. Entry
functions use the original HIA R/W/W ABI. Two-read owners expose an ordinary R/W/W
wrapper whose second operand is only borrowed read-only by HIA; the fixed caller
must actually map both input operands read-only.

Offsets are absolute within the named buffer. Capacity is the actual logical
descriptor extent, not mapped page size. All buffers and registries remain owned
by their issuing session. No input or result view may outlive its immutable
lease. All integer arithmetic used for extents is checked before address use.

Return values are 128 for a complete event, 0xfffffffe for this owner's workspace
GROW, and 0xfffffffd for private ABI failure. A BAD lease is discarded even when a
short supplied workspace cannot physically hold a persistent poison word.

## Tape input and event

The tape owner has three operands:

- first: the complete immutable HIAGRF01 Graph of [admitted Core, checked plan];
- second: the actual successful planner workspace, including its HIAPFE01 event
  and HIAPFN01 plan;
- third: private mutable output/workspace, initially at least 12,288 bytes.

This owner is pure. Each GROW repeats the complete calculation on the same two
immutable inputs. It first counts all records/string bytes, then writes exactly
that amount. It imposes no additional language function, block, operation or
session quota.

The event is 16 words at workspace offset zero:

| Word | Meaning |
| --- | --- |
| 0..2 | HIAFLE01, version 1, action |
| 3..5 | actual frame lease, actual frame request, function index |
| 6 | exact needed workspace |
| 7..8 | header offset 12,288 and tape byte extent on success, otherwise zero |
| 9..11 | record count, serial after complete tape, original frame bytes |
| 12..14 | zero |
| 15 | private ABI reason, otherwise zero |

Actions are 0 success, 1 GROW, 3 BAD. A Function frame semantic refusal never enters
this owner.

The 32-word tape header at offset 12,288 is:

| Word | Meaning |
| --- | --- |
| 0..4 | HIAFLT01, version 1, frame lease, frame request, function index |
| 5..9 | record count, records offset 12,544, string pool offset, pool bytes, used absolute extent |
| 10..11 | serial after original trap allocation, serial after complete tape |
| 12..14 | original function-name offset, name bytes, original frame bytes |
| 15..17 | complete source Graph bytes, source root ID, used actual frame workspace |
| 18..31 | zero |

Each record is 128 bytes / 16 words:

| Word | Meaning |
| --- | --- |
| 0..3 | original Code operation ID, argument count, serial before that Code command, observation effect |
| 4..12 | three argument triples: kind, value/offset, byte count |
| 13..15 | zero |

Unused argument triples are zero. Argument kind 0 is a nonnegative integer,
kind 1 is a nonzero negative magnitude; both use a zero byte-count field. Kind 2
is an ASCII string completely copied into the tape string pool. No references
to reusable original Core/plan bytes remain in command arguments.

Operation IDs are exactly those of the frozen x64 protocol. The tape emits
operations 2..44 except raw emit 3. It never uses host-side machine-byte encoding.
Effect 0 is an ordinary command. Effect 1 is the initial offset query, effect 2
is a block-end offset query, and effect 3 is the final offset query. Nonzero
effects require operation 2. There is exactly one initial/final observation.

## Code issuer input and lifecycle

The issuer's first operand is the actual immutable tape workspace. Its second is
the actual encoder metadata workspace, temporarily read-only for the issuer.
Its third operand is its private persistent workspace, initially 8,192 bytes.

The caller writes a 128-byte control block at offset 128:

| Word | Meaning |
| --- | --- |
| 0..2 | HIAFLC01, version 1, issuer lease |
| 3..5 | logical request, issuer control sequence, kind |
| 6..7 | actual Code lease, actual Code event sequence |
| 8..10 | actual frame lease, actual frame request, function index |
| 11..13 | used tape extent, actual Code buffer capacity, actual Code return value |
| 14..15 | zero |

Kind 1 begins from a successful actual Code event. It requires issuer control
sequence 1 and a zero persistent state. Kind 2 acknowledges the sole pending
actual Code command, with the next issuer control sequence and exact Code
correlation. Code return is 128 or its actual GROW return; Code BAD always retires
the issuer lease.

Persistent state is workspace [256,448). Event scratch is [0,128), control is
[128,256), temporary scratch begins at 512, constant error text is at 2,048, and
a new complete command or result begins at 4,096.

This lease processes exactly one Function. Its actual Code lease may precede and
outlive this lease. The parent Emitter must sequence multiple Function leases
against that same actual Code state and use actual result serials/metadata.

The 16-word event at zero is:

| Word | Meaning |
| --- | --- |
| 0..5 | HIAFLIE1, version 1, action, issuer lease, request, issuer control sequence |
| 6..10 | function index, Code lease, Code sequence, tape record index, committed serial |
| 11..12 | payload offset and bytes |
| 13..14 | action-specific auxiliary words |
| 15 | private ABI reason, otherwise zero |

| Action | Return | Payload / auxiliary meaning |
| --- | --- | --- |
| 0 DONE | 128 | complete HIAFLR01 result capsule |
| 1 CALL | 128 | complete native HIAXCC01 + HIAXGR01 packet; no host interpretation is needed |
| 2 ERROR | 128 | full original UTF-8 message; aux1 is error domain, aux2 original numeric error |
| 3 BAD | FD | private permanent poison; discard the lease |
| 4 own GROW | FE | aux1 exact needed issuer workspace; persistent state is unchanged |
| 5 Code GROW | 128 | the same pending packet; aux1/aux2 actual Code/metadata capacities requested |

Error domain 1 is the original MachineEncodingError, with original Code error ID.
Domain 2 is HIAProgramNativeRejected, currently the exact original block-end
16 MiB text error, with error ID 1.

For own GROW, grow the issuer workspace while copying all old bytes, then replay
the same control and same actual immutable tape/Code reply. No ACK or serial has
been committed. For Code GROW, forward the original actual event to the issuer;
after action 5, grow the exact requested Code buffers preserving every byte and
replay the same native command packet. This is not a second command. The Code
sequence does not advance until the original command completes.

All terminal semantic errors retain the actual partial Code state. A semantic
terminal cannot be resumed as a new Function; a new issuer lease is necessary.
No serial, label, fixup or relocation rollback is fabricated.

## Complete Function result

DONE publishes a 256-byte HIAFLR01 header followed by complete copied function and
symbol names. All offsets are within the current issuer workspace:

| Word | Meaning |
| --- | --- |
| 0..4 | HIAFLR01, version 1, issuer lease, request, function index |
| 5..6 | actual Code lease and last Code sequence |
| 7..10 | begin offset, end offset, original frame bytes, resulting original serial |
| 11..14 | function-name offset/bytes, native symbol-name offset/bytes |
| 15 | exact complete capsule bytes |
| 16..31 | zero |

The native symbol is the exact original "__hia_native_fn_" plus the original
function index. Its original symbol size is end minus begin, global is false,
and the frame list entry is the complete original function name and frame bytes.
The parent must copy or consume these views before any later call/growth can
reuse the workspace.

## Original ordering and limits

The planner applies the original frame limit before allocating the trap serial.
Tape emission records labels/serials at the exact original Code call boundaries.
The issuer commits a serial when its command is issued, as the original parent
label allocation already happened before that Code method.

After each original block, HIA asks the actual Code encoder for its offset and
checks strictly greater than 16 MiB. It does not count estimated machine bytes.
After the last successful block, the original trap label, call abort and UD2
remain. Consequently a single Function can finish at 16 MiB + 7. The original
whole Emitter's later final text gate remains an explicit upstream obligation.

At the original 64 MiB Code boundary, an emitted branch/call prefix and its
fixup/relocation can precede the later failing displacement write. The issuer
preserves that exact partial mutation and full original error.

The original 1,024-function and 4,096-block Core input domains are not reduced to
the compiler's bootstrap authoring profile. New owner source generation remains
subject to the unchanged bootstrap 128-function / 1,536-block / 8,192-operation /
256-block-per-function / 16-block-parameter gates and the actual original B3
compiler. There is no additional 128-operation-per-block gate.

## Proposed independent actual test schedule

The new CI proposes 39 independent test processes, each with CPU 90 seconds,
wall 180 seconds, address space 1 GiB, and core size zero:

| Group | Processes | Planned cases |
| --- | ---: | ---: |
| smoke: all types and serial boundaries | 1 | 25 |
| scalar arithmetic/bit/compare/constants | 10 | 240 |
| integer casts | 10 | 200 |
| booleans and branch/CMOV scalar selection | 1 | 32 |
| all byte-resource/chain operations and loan.end | 1 | 30 |
| block orders, staged backedges and selected registers | 1 | 21 |
| scalar/multiword/resource call results | 1 | 12 |
| all scratch/immediate/select option products | 1 | 16 |
| original function/block/frame inventory boundaries | 5 | 5 |
| actual 16 MiB/64 MiB Code prefixes and partial writes | 6 | 6 |
| malformed tape source/frame/extent and pure replay | 1 | 59 |
| pending ACK, GROW, permanent poison and short-work controls | 1 | 72 |
| Total | 39 | 718 |

There are 129 planned private negative controls. The 4,096-block and 8,184-value
extreme cases compare the complete native tape against the complete original
Function's Code-call trace; they do not execute each Code ACK in those two cases.
The 8,185-value case compares the original frame refusal with unchanged actual
Code. Other nonprotocol cases execute actual native commands and, on success,
the actual finalizer. These categories are independently counted in the report.

Every actual entry records all three buffers before and after, all returned
words, real native elapsed time, physical read-only checks and guard canaries.
Every buffer byte is read; only immutable 4 KiB pages are content-deduplicated
using lossless zlib. Each new page is decoded and compared immediately; all pages
are decoded and rehashed at completion. Exact per-entry snapshot mappings retain
all logical bytes. Source/image files are read again. Original errors and
partial states are compared without masking fields.

The original Function and Code classes operate only as independent comparison
oracles. Reading the actual native packet for comparison never produces the
packet supplied to the encoder: the complete actual packet bytes are forwarded
unchanged. The finalizer's complete machine bytes and relocation list are
compared, as are labels, pending fixups, serials, symbol metadata and frame data.

The build executes five fresh B3 compilations, each preserving CPU 10 seconds,
wall 20 seconds and address space 256 MiB. It records source/image/runner hashes,
original compilation receipts and the profile of each image. A failure preserves
the complete current run and nested compiler stderr. Neither successful source
syntax nor successful dependency compilation is a claim of runtime correctness.
