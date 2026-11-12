# Native scalar and borrowed-byte wrapper leaves

Status: new authoring and an unexecuted independent CI corpus. No wrapper
generation, B3 compilation, VM result or actual native result is inherited from
the Function, frame or x64 component qualifications.

## Exact source boundary

The reference is commit 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5:

- hepta/hia_program_native.py, SHA256
  bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c,
  complete _Emitter.wrapper, _normalize, _prologue and label/function_symbol.
- hepta/hia_native_byte_abi.py, SHA256
  0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6,
  complete emit_wrapper. Its normalize_exports is an upstream dependency,
  used only as an independent oracle / fixture checker in this component's test.

The two new HIA kernels decide the original wrapper instruction choices and
convert the resulting complete native tape into real Code commands. The
existing actual x64 encoder and finalizer receive those exact command bytes.
The development caller forwards buffers, capacities and raw return codes; it
does not manufacture instruction arguments, labels, register assignments or
machine bytes. A Code initialization and optional NOP prefix in the corpus
are explicit fixture preconditions, not an implementation of the whole Emitter.

The original frame limit is 65,536 bytes. Every prologue touches each 4,096-byte
interval. Borrowed-byte extent is 1..1,048,576, with 1..8 loan ranges. The
component does not add a wrapper-local 16 MiB check: the whole Emitter owns its
original final text gate, after all functions, alignments, wrappers and export
checks. The actual Code owner keeps its original 64 MiB/partial-write behavior.

## Input ownership

Both kernels use R/R/W entry buffers. As in the existing HIA assembly ABI, the
public three-buffer wrapper borrows the second mutable ABI operand read-only
before calling the internal R/R/W function. Both immutable operands must remain
the same actual private issued objects through GROW and continuation.

The first wrapper-tape buffer is the existing exact HIAGRF01 Graph of
[admitted Core, checked machine plan or null]. The original Core/plan issuers
remain responsible for language admission. No header, lease, hash field or
nonce is external authentication.

The second buffer is exactly 96 bytes, twelve little-endian u64 words:

| Word | Meaning |
|---|---|
| 0 | HIAWRC01 |
| 1 | version 1 |
| 2 | actual Graph lease |
| 3 | nonzero logical request |
| 4 | original Core function index |
| 5 | incoming Emitter label serial, including zero |
| 6 | actual Graph root node |
| 7 | wrapper kind: 1 scalar, 2 normalized borrowed byte |
| 8 | zero for scalar; actual normalized borrowed extent otherwise |
| 9..11 | zero |

For scalar mode, native HIA derives eligibility from the actual Core export
contract and complete signature. An ineligible wrapper is skipped before any
reserved-name rejection. For borrowed mode, a real upstream normalized manifest
must have issued the selected name and extent. Private malformed signature,
export-contract and manifest inconsistencies are BAD, not new public language
errors. Full native normalization of an arbitrary foreign opt-in manifest is
not claimed by this leaf.

## Tape event and tape

The tape workspace minimum is 12,288 bytes. The component is a pure same-input
two-pass operation: first measure all records and copied strings; then, once the
entire result fits, write the complete tape. It never reserves a partial public
Code mutation. GROW requires the exact same immutable operands.

The 128-byte event is sixteen u64 words:

| Word | Meaning |
|---|---|
| 0..1 | HIAWRE01, version 1 |
| 2 | 0 tape, 1 GROW, 2 original semantic rejection, 3 BAD, 4 skipped |
| 3..5 | Graph lease, logical request, original function index |
| 6 | required workspace bytes |
| 7..8 | tape header offset and tape bytes on success; otherwise zero |
| 9 | complete number of Code records |
| 10 | resulting Emitter label serial |
| 11 | wrapper frame bytes |
| 12..13 | complete original error text offset and bytes only for action 2 |
| 14 | semantic error ID: 1 reserved scalar name, 2 scalar frame, 3 byte frame |
| 15 | private ABI refusal reason |

Return is 128 for actions 0/2/4, FE for GROW, FD for BAD. A workspace shorter
than the minimum returns FD without a valid event; it is not a persistent lease
and does not promise to store poison in inaccessible bytes.

The tape starts at 12,288 with 32 u64 words. It preserves the Function tape
layout at words 0..17, but has magic HIAWRT01; word 17 is the exact 96-byte
input command extent. Word 18 is wrapper kind, word 19 is extent, words
20..31 are zero. Code records begin at 12,544, each 128 bytes. Every string is
fully copied into the tape's measured string pool.

Records preserve the existing complete Code opcode/typed-argument dialect.
The first record is an actual offset query with effect 1, the final record an
actual offset query with effect 3. All intermediate wrapper records have effect
0. Effect 2, the Function block text-budget observation, is not legal here.
The recorded label serial is the original serial at that exact Code call.

Scratch regions are disjoint: the state ends before 768; arguments start at
768; eight 256-byte temporary label rows occupy 1,024..3,071; literal index
starts at 3,072 and its data at 6,144; eight range rows occupy 8,192..8,319;
the output begins at 12,288. Authoring asserts the complete literal table ends
at or before 8,192. Temporary strings are copied when each tape record is
issued, so a later range/disjoint label cannot alias an earlier record.

## Exact wrapper semantics

Scalar wrappers capture all arguments using rax before any scratch operation.
The first six input words use rdi/rsi/rdx/rcx/r8/r9; later words use the original
rbp+16 stack displacement. Integer/boolean normalization, result handling,
internal function symbol, public symbol and serial are unchanged.

Borrowed wrappers expand each loan into pointer/length in place. They capture
all scalar and expanded words first, allocate the four failure labels in the
original 1/2/3/4 order, then perform:

1. For each range in original parameter order: extent, admitted-empty bypass,
   nonempty null, unsigned pointer+length carry.
2. For each original i<j pair with at least one mutable range: zero-length
   bypasses, both disjoint interval comparisons, then alias failure.
3. Actual internal call, canonical u32 return, normal leave/return.
4. Original four failure blocks, packing status in the high 32 bits.

The native tape preserves every original Code method, argument, label spelling
and serial boundary. It never dereferences caller byte pointers during guards.

## Actual Code ACK issuer

The issuer minimum is 8,192 bytes. Its command at workspace offset 128 has the
same sixteen-word shape as the Function issuer, with magic HIAWIC01; the
actual wrapper tape lease/request replace the Function tape fields.
Persistent state remains at 256..447. Event magic is HIAWIE01 and persistent
magic HIAWIS01, so a Function session is incompatible.

Actions retain the original meanings:

- 1: call actual Code with the native HIAXCC01 view.
- 5: grow actual Code arena/metadata, repeat that exact immutable pending packet.
- 4: grow this issuer workspace before commit; replay the same control/input.
- 0: complete metadata, after the actual final offset ACK.
- 2: complete actual Code error text; preserve the real partial Code state.
- 3: permanent private ABI poison; the caller must retire the lease.

The issuer accepts incoming serial zero. Its new namespace rejects wrapper
effect 2. It adds no Function block budget or whole-Emitter limit.

DONE metadata begins at 4,096 with a 256-byte HIAWIR01 header. Words 0..15
retain the Function result correlation/actual Code begin/end/frame/serial and
name/symbol-view fields. The actual original name bytes follow immediately.
Name and symbol views refer to the same complete copied public name. Word 16 is
kind, word 17 extent, word 18 global=1, words 19..31 zero. There is no host
function-prefix construction and no retained borrowed pointer into reused
Code metadata.

## Independent actual corpus to be executed

The new driver compiles four kernels (wrapper tape, wrapper issuer, original
x64 encoder, original x64 finalizer), retaining their canonical HIA, parsed
document, profile, actual image and complete compiler receipts. All authoring
and execution dependencies are frozen and reread.

The planned 26 groups contain 502 cases:

- Eleven scalar groups: 286 cases over every scalar input and every supported
  result shape, register and stack inputs.
- Eight borrowed groups: 72 cases, 1..8 loans, read/mutable/mixed combinations,
  mixed scalar/register/stack placement and extent endpoints.
- Sixteen checked machine-plan encoding combinations.
- Thirty-two reserved-name/skip ordering cases and eight signature skips.
- Four explicitly private stack-pressure cases. The exact-limit cases measure
  and compare the complete native tape; they do not claim an admitted public
  Core or an actual Code run for 8,191 input words.
- Two real Code budget cases: no wrapper-local 16 MiB rejection, and exact
  original partial Code state at the 64 MiB boundary.
- Eighty-two protocol/repeat/serial/format-pressure cases, including 79 private
  negative controls and a real issuer result GROW.

Planned actual wrapper chains: 378 (377 successes, one actual Code error).
Other categories: 18 original wrapper semantic rejections, 24 skips,
2 complete-tape-only extremes, 79 private controls, one pure repeat.
These are fixed planned corpus counts, not observed results.

The original classes, functions and byte-wrapper source execute only as the
independent reference. Full Code method traces, all text bytes, labels,
fixups, relocations, public symbols, frames, serial and full errors are compared.
Every actual input/output/workspace is read completely before and after every
native entry with RO mappings and guard/canary checks, stored in lossless 4 KiB
content-addressed pages, then reconstructed and rehashed.

Each new test group keeps 90 CPU seconds / 180 wall seconds / 1 GiB / no core.
Every B3 compilation keeps 10 CPU / 20 wall / 256 MiB. Original profile bounds
remain 128 functions / 1,536 blocks / 8,192 operations / 256 blocks per function /
16 block parameters / SSA suffix below 2,048. There is no new 128-ops/block gate.

## Remaining owners

The complete Emitter orchestration still must own original profile validation,
function-order realization, Code initialization, function and wrapper alignment
(including skipped wrappers), actual Function+wrapper accumulation, explicit
missing-export diagnostics, 1..128 export gate, final 16 MiB gate, Code finalize,
complete ELF writer and final object inventory. Public revalidation, target and
machine-plan/borrowed-manifest normalization, implementation identity, artifact
publication and installed dispatch remain their separate existing contracts.
This wrapper component alone closes none of those owners, and is not a cold
qualification or a complete pure-HIA build chain.
