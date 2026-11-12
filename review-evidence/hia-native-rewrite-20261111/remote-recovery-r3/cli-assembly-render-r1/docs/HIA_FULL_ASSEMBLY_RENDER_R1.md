# Complete public assembly renderer component — new development revision

Status: AUTHORING_ONLY / UNEXECUTED. No prior native, CI, cold or installed result
is inherited. This is the text producer in the complete three-action assembly
migration; it is not the whole public renderer or its admission coordinator.

## Original contract and order

The reference is exact commit 0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5,
hepta/hia_agent_assembly.py (15,216 bytes,
SHA256 e37095496bf159ad573a31214d4d73e916648b4f0664edb541014f54681fbc03).

The original public render_assembly first calls verify_program on the original
input. It then rejects structured/composite inputs, even if their lowered Core
has an otherwise supported schema, and rejects primitive schemas other than
v6/v7/v8. Only after that gate does it produce the complete text, pass that text
through fresh assemble_program, and compare the exact canonical Core bytes.

This component preserves the complete text and profile gate. Its fixed native
coordinator must still obtain actual initial admission, bind the actual Core
and structured flag to that admission, run the complete syntax/object/primitive
roundtrip after rendering, and compare canonical Core bytes. Header equality
alone provides none of those authorities.

Rendering has no early 1 MiB, 16,384-line, 16,384-byte-line, 256-function,
4,096-global-block, 16,384-operation or 256-list-item admission. Those are the
later assembly parser's policies. In particular an admitted 1,024-function Core
must be completely rendered before the original 256-function syntax refusal.
An admitted Core whose text exceeds 1 MiB must be completely rendered before
the source-byte refusal. The retained original Core input limit is 8 MiB.

## Private input ABI

Semantic entry: R / R / W. The ordinary generated wrapper has R / W / W and
borrows its second operand read-only. A production image table therefore must
mark this role as two-read; a different R/W/W peer must not inherit that bit.

First view is the exact complete immutable admitted Core JSON, length 1..8 MiB.
The source is not arbitrary external JSON. The caller retains it until this
operation terminates, across all GROW events. The second view is exactly 96 bytes,
12 little-endian u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAARC01 |
| 1 | ABI version 1 |
| 2 | Nonzero session lease |
| 3 | Nonzero operation sequence |
| 4 | Exact first-view byte length |
| 5 | Actual admission's structured-input flag, exactly 0 or 1 |
| 6..11 | Zero |

The private workspace has a minimum of 8,192 bytes. Offsets, not raw pointers,
are retained. The component measures physical arena requirements, requests
GROW, copies the source, decodes it with the retained integer JSON grammar,
counts the complete rendered text, requests the exact final capacity, and emits
all text. The fixed caller copies the complete old workspace on growth and
retries the same immutable source and command; it does not repeat admission.

Before the source copy, immutable source custody is a fixed-caller obligation.
After the counting pass, every source byte and all 96 command bytes are compared
on output-GROW retry. A matching lease/header is not source authentication.
Persistent state/mapping remain private to the fixed executor.

## Complete event ABI

At workspace offset 256, 128 bytes / 16 u64 words:

| Word | Meaning |
| --- | --- |
| 0 | HIAARE01 |
| 1 | 0 complete text, 1 GROW, 2 profile refusal, 3 private ABI failure |
| 2 | Session lease |
| 3 | Operation sequence |
| 4 | Profile error ID: 1 only for profile refusal; otherwise 0 |
| 5..6 | Zero |
| 7 | Workspace-relative complete result offset |
| 8 | Complete result bytes |
| 9 | Zero |
| 10 | Exact original source byte length |
| 11 | Exact needed workspace capacity on GROW |
| 12..15 | Zero |

Return 128 accompanies complete text or the original profile message.
Return 0xfffffffe accompanies GROW. Return 0xfffffffd is private ABI failure;
the fixed caller discards the lease and does not trust a stale result event.

The profile text is exactly:
E_HIA_ASSEMBLY_PROFILE: render requires explicit primitive v6/v7/v8 Core; use the existing adapter first

All workspaces meeting the full minimum persistently reject after BAD. A shorter
invalid borrow cannot safely maintain the full private state and must be
discarded by the caller. Neither success nor semantic-profile terminal can be
reused as a new operation.

Result views are borrowed only from the current workspace. A later call,
retirement, release or workspace replacement ends that borrow. The coordinator
must protect/copy the actual result before issuing a separate parser operation.

## Renderer details

Root schema/module and optional exports, complete function signatures/effects/
entry/optional return_loans, all block parameters, instructions, attributes and
ret/jump/branch/trap are emitted in the original order. Optional empty exports
and absent exports are distinct. Explicit return_loans remains present.

Attributes use full compact sorted-key JSON with ensure_ascii=False, including
decoded Unicode key order, short/control escapes, strings, arrays, maps, exact
integer lexemes, booleans and null. Integer negative zero is normalized to zero.
For admitted Core, parameter-bound loan names are ASCII or null, so the original
default-ASCII return_loans JSON has exactly the same bytes as this output.

The decoder is an AST offset rebasing of the original generator
tools/generate_hia_json_decode.py
(SHA256 fffc97c704cc75ad88239fe79d7b7f83418199a732364f834e006ebfd5f8548f)
and tools/generate_hia_json_preflight.py
(SHA256 293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c).
The exact loaded source constants are compared to the single frozen file read.
Grammar is retained; only the original node-count export, private buffer-offset
rebasing, and u64 return representation are changed. Original <=8 MiB /
262,144-node / depth64 admitted Core is within those arithmetic bounds.

## New verification inventory

The proposed independent test builds one real HIA image using the unchanged
f50 B3 (669,556 bytes, SHA256
35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b).
B3 remains 10 CPU seconds / 20 wall seconds / 256 MiB. The full new component
test process remains 90 CPU seconds / 1 GiB / no core dump; its enclosing
aggregate CI command is bounded separately. No result is claimed yet.

The planned 309 public fixtures use exact reference verify_program first, with
its actual canonical bytes and structured flag. They compare every native
output byte to the original renderer helper, and separately record the full
public renderer's mandatory late roundtrip result. They cover all scalar
integer widths and extrema, bool/unit, arithmetic, casts, traps, calls, branch
and jump, all three supported schemas, five historical profile refusals,
real owner/loan/recursive/returned-loan fixtures, optional exports, lists,
256/257/1,024 functions, long valid identifiers, 4,096/4,097 global blocks and
an admitted Core producing more than 1 MiB of complete text.

The separate planned 69 private construction fixtures grant no Core authority.
They exercise recursive sorted attribute serialization, Unicode/control
escaping, exact kinds, private large integers, differently ordered dictionaries
and nested arrays/maps. They compare only construction-text bytes and are never
counted as public admitted programs.

The planned 41 private protocol controls cover all header/reserved fields,
command extent, short workspace, empty/oversized input, invalid state, permanent
poison, terminal reuse, output-GROW source/header/layout/count substitution and
actual malformed JSON. All native calls save complete source/command/workspace
before and after plus guards and actual return values as lossless zlib CAS,
with immediate decompression readback. Failure records are written before
assertions. The complete original profile/manifest/compiler receipts and
source/image before-and-after identity are retained.

These are planned counts, not observed PASS. The original reference's own
semantics and errors remain the oracle, and the native component has no host
rendering fallback. Native full admission, native roundtrip, three public CLI
routes, assembly publication, installed dispatch and cold qualification remain
separate integration obligations.
