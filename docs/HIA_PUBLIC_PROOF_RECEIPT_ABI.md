# Public proof receipt private role ABI

Qualified private HIA receipt and JSON components. The current receipt component passes the original 391 comparisons plus 19 large-claimed and large-fresh boundary controls. These are component gates; an enclosing public owner must actually normalize, recompute the proof, capture identities, and enforce lifetime rules before supplying the fresh receipt. No caller metadata or arena is authority.

## Components

The runtime sources are `examples/hia_bootstrap/native_public_proof_receipt.hepta` and `examples/hia_bootstrap/native_public_proof_json.hepta`. Current independently compiled products are:

- receipt: 513620 bytes, SHA256 `9bd5cc7b00a04cd4710406951d8b07348d83832479591c1168fe56841cb3f324`;
- JSON: 123595 bytes, SHA256 `bbb894c08d02cff36080a8dfa3eb3c6846ac1aa2095eb2851414585fb45c4f04`.

Both have the ordinary six-word (source, source_bytes, output, output_bytes, work, work_bytes) ABI. Distinct private extents; no aliases. Source is immutable. Return u32.

## JSON decoder

Exact existing generate_hia_json_decode.source_program(wire_spans=True), independently compiled by the sealed 494833 compiler. Source is the raw JSON alone, without its enclosing binary reply/header.

Use max_nodes=131073 at work+48, max_depth=128 at work+56. Output capacity 16 MiB and workspace 8 MiB cover the receipt/diagnostic profile, whose source is at most 1 MiB. On success return used arena bytes >=64; preserve only those bytes. Native decoder refuses malformed UTF-8, grammar, duplicate decoded object keys, depth/nodes and insufficient extents with the original u32 error values.

Arena header 8Q: magic 5208772604367785521, count, decoded-string-base=64+72*count, used, used, original_JSON_bytes, version1, reserved0.
Each 72 B row: kind, parent, next sibling, scalar start/first child, scalar length/child count, decoded key offset, decoded key length, raw JSON value offset, raw JSON value length. Kinds 0 null,1 false,2 true,3 number,4 decoded string,5 array,6 object. For kinds 0..3 use row+24/+32 as raw source span; strings/containers use row+56/+64. String/key offsets are arena-relative. NONE=UINT64_MAX.

## Receipt owner input

Input header 768 B, magic HIAJPR01 at 0, followed by six exact variable tails:
A JSON, A arena, B JSON, B arena, diagnostic JSON, diagnostic arena.
All arenas must be produced freshly by the embedded decoder from the paired captured JSON in the same invocation. They are never caller-authoritative serialized evidence.

Header words:
- +8 action: 0 patch captured private proof, 1 build unknown, 2 verify receipt against freshly patched proof, 3 precheck claimed receipt and select its function.
- +16 property mode 1 totality, 2 translation (verification also 2 here).
- +24 original primitive reason id for action1; see the V8 primitive LITERALS. 1 invalid timeout; 2 invalid before/program; 3 invalid after; 12 deadline; 13 identity; 14 component unavailable; 16 missing/ambiguous function, etc.
- +32 complete parent wall_ns (measured from original call start).
- +40 original requested timeout_ms.
- +48 explicit/selected ASCII function byte length 0..128; bytes at +512; zero means None.
- +56 flags: bit1=raw-before hash available; bit2=normalized-before/core hash available; bit4=raw-after; bit8=normalized-after; bit16=whole public image hash; bit32=public source-inventory hash; bit64=use original diagnostic for action1; bit128=disable all canonical/proof claims after deadline/identity/component failure; bit256=explicit complete diagnostic/fresh-unknown profile; bit512=explicit large claimed receipt for actions2/3 only. The extension rules below are mandatory; all other bits refuse.
- +64 raw before SHA256 bytes32.
- +96 raw after SHA256 bytes32.
- +128 original-canonical before SHA256 bytes32.
- +160 original-canonical after SHA256 bytes32.
- +192 primitive Core before SHA256 bytes32.
- +224 primitive Core after SHA256 bytes32.
- +256 actual public whole image SHA256 bytes32.
- +288 actual embedded private primitive engine image SHA256 bytes32 (the V8 df1c7eaf... image; hash the actual embedded bytes).
- +320 public checker inventory SHA256 bytes32. Exact hash input is UTF-8 compact JSON {"native-closure.image.bin":"<lowercase whole public SHA>"} with no whitespace or trailing newline.
- +352 A JSON bytes; +360 A arena bytes.
- +368 B JSON bytes; +376 B arena bytes.
- +384 diagnostic JSON bytes; +392 diagnostic arena bytes.
- +400 reserved0.
- +408 captured private outcome 0 unknown/1 proved/2 disproved; for non-patch modes zero is allowed.
- +416..511 reserved0.
- +512..639 function bytes then zero pad.
- +640..767 reserved0.

Each JSON <=1MiB; each arena <=16MiB. Either both JSON and arena sizes zero or both nonzero. Tail extents are exact. Output >=1MiB, workspace >=8MiB. BAD=0xfffffffd; no result authority on BAD.

## Operations

Action0 receives A=captured V8 JSON (remove HIAMVR01 header first) plus its freshly parsed arena. It checks exact schema/profile/status and that validator_sha256 and checker.source_identity bind the actual embedded private ELF hash. Actual Core/input hashes in both root and subject must match the separately captured primitive Core identities; null is allowed only for an unknown private result. Root/subject selection must agree, and an explicit selection must equal the owned request name. Positive results require both canonical identities, whole-image and inventory identities, and no disabled-claim flag. It replaces canonical input hashes, raw request hashes, parent validator/checker/solver identities, parent wall_ns and original timeout. It retains the actual solver discharge and independently replayed counterexample. Program/Core identities are the actual separately hashed normalized Core.

The subject excludes raw request hashes: original receipt scope binds canonical original/Core bytes, so different whitespace in equivalent original JSON does not stale a proof. Raw request hashes remain top-level audit metadata. No duplicate keys are appended.

Action1 emits an unknown receipt with the same canonical scope and original partial-verification order. It uses the mode/reason/identity flags. When flag64 is set, diagnostic JSON must be actual role4 output from the same captured normalizer FD and same absolute deadline: its first diagnostics item has code E_DRIVER and message E_HIA_*: <message>. The output validation_error.code is the exact E_HIA_* prefix, and validation_error.message is the full original decoded message, including the prefix. Both are escaped safely.

Action3 receives B=caller receipt raw JSON plus its native arena. It first enforces original schema translation-validation.v1 and status proved. On success the selector reply is 64 B plus ASCII function bytes: magic HIAVRG01; +8 name length; remaining header zero. A null or missing function produces zero length. Invalid claimed proof produces ordinary error reply described below. For invalid function types/extent/encoding it rejects with current-program/profile receipt error. The outer owner uses the explicit request name if provided; otherwise it uses the selected receipt name before fresh proof.

Action2 receives A=the newly patched JSON plus a newly parsed A arena, and B=the caller's original JSON/arena. It first performs original receipt schema/status precheck, then compares original string binding keys in original order: schema, profile, function, scope, before_sha256, after_sha256, before_input_sha256, after_input_sha256, validator_sha256. It requires the fresh result to be proved, then compares exact plain JSON values of subject/property/profile/assumptions/checker/unproved_obligations/proof_scope_schema/proved_meaning/execution_authority. Object order and string escaping do not matter; arrays and JSON types do. Raw request audit hashes are not in the subject. Extra claimed fields do not grant authority; only the freshly computed result is returned.

Receipt scope currently contains no floating-point values. Numeric scope comparisons retain integer -0/0 equality; decimal/exponent representations cannot masquerade as an integer scope value.

## Output

Actions0/1: normal HIAMVR01 64 B header: magic, property mode, status0..2, JSON length, parent wall_ns,0,0,0. JSON follows.

Action2 success: HIAMVR01 with mode3/status1 and the freshly computed JSON.
Action2/3 refusal: HIAMVR01 with mode3/status3 and {"status":"error","error":{"code":...,"message":...}}. Codes/messages reproduce the original receipt errors:
- E_HIA_TRANSLATION_RECEIPT / translation receipt does not claim a supported proof
- E_HIA_TRANSLATION_RECEIPT / translation receipt is not bound to the current program/profile
- E_HIA_TRANSLATION_UNPROVED / translation proof could not be recomputed: <fresh reason>
- E_HIA_TRANSLATION_RECEIPT / translation proof scope is missing, stale or altered

Public front-end requirements: same immutable raw inputs, same captured/sealed normalizer for admit/diagnostic, verified HIAVCF01 extents/profile, actual SHA hashes of all three byte identities, original before/after error order, one original absolute proof deadline across normalization, private proof and closure. The qualified HIAMVP02 child receives that unchanged absolute deadline and the original timeout; required normalization/admission errors finish before the original proof checkpoint under a separate once-computed transport lifetime. See HIA_PUBLIC_PROOF_DEADLINE.md; no remaining-time rounding or child budget renewal is used. Before returning a proved/disproved patch, recheck parent wall and whole-image identity; deadline/identity/component failures build unknown and disable claims. Release/caller receipt verification always recomputes.

## Qualification and limitations

The sealed 494833 compiler built the current receipt source (442692 bytes) within the unchanged 65-function / 1289-block / 7816-operation profile. Exact source, compiler, product, and original-oracle report identities are recorded in HIA_PUBLIC_PROOF_RECEIPT_QUALIFICATION.json.

The original ASCII private selector remains bounded at 128 bytes, with zero length meaning None. The outer typed owner must use the common public_proof_typed/public_proof_values components to preserve empty strings, non-string values, exact timeout types and their original validation order. The older action3 ASCII selector alone is not a substitute for that typed selection sequence. The complete original normalizer diagnostic bound and immutable deadline behavior are documented below and in HIA_PUBLIC_PROOF_DEADLINE.md. Final unified public/MV integration and release activation are separate gates.

The original verification-policy oracle receives a frozen fresh result for these pure-component comparisons; it does not rerun the solver during those decision-policy tests. Actual fresh proof recomputation and all process custody/deadline paths must additionally pass in the enclosing native public service. No caller arena, metadata flag, digest, serialized receipt, or component unit test grants execution authority.


## Explicit complete diagnostic profile

The legacy flag domain (0 through 255), legacy JSON limits, original action
semantics, and positive claim bindings retain their qualified behavior. The
additional flag bit 256 is a private, caller-owned diagnostic extension. It is
accepted only for action 1 with diagnostic bit 64, or action 2 without bit 64,
with `actual_private_outcome == 0` and a fresh A receipt whose status is
`unknown`. It cannot widen the domain of proved receipts.

In action 1 only diagnostic JSON may use a 64 MiB raw extent. In action 2 only
fresh unknown A JSON may use that extent. Other JSON segments retain their
1 MiB bounds unless the separate large-claimed bit 512 applies. Diagnostic arenas
retain 16 MiB. The explicit fresh-unknown action2 arena may use up to 80 MiB
to preserve a complete typed function value repeated in root and subject. All
arenas retain the same 131073-node limit.
The decoder uses the same complete JSON/duplicate/UTF-8 checks. For raw JSON
larger than 8 MiB its workspace word at offset 120 must be the little-endian
magic `HIAJLG01`, and its output extent must be at least 80 MiB; this is an
explicit private profile, not a changed default decoder limit.

The diagnostic is the actual first `E_DRIVER` record from the sealed
normalizer. Its decoded message starts with a checked `E_HIA_*: ` prefix.
The original whole-Core diagnostic capacity is
`input_bytes + min(262144, (input_bytes + 1) // 2 + 1) + 4096`, at most 8654848
bytes for the existing 8 MiB source bound. The generated single-diagnostic
JSON report has 144 fixed bytes outside its quoted message. Even the
conservative six-byte-per-input-byte JSON escaping bound plus this fixed
report is below 64 MiB. The process capture limit is unchanged.

The large message is never copied into the old 1 MiB text region. The native
receipt owner validates the arena and the message's actual raw JSON span,
then appends that complete quoted span to the rendered unknown receipt. The
short code prefix alone uses the old text region. A small output extent
refuses without writing beyond it. The fresh-verification action continues
its original schema, binding, proof-status and exact-scope comparison order.

This closes diagnostic extent transport for the stated producer. It does not
claim full publication/call composition or whole-release qualification. The
separate immutable-deadline and typed-component evidence retains its own scope.


## Explicit large claimed receipt profile

Bit 512 is accepted only for actions 2 and 3. It allows the claimed B JSON up to 64 MiB and its same-invocation decoder arena up to 80 MiB. The unchanged decoder uses its explicit HIAJLG01 profile above 8 MiB. No positive proof is granted by this flag. Action 2 still checks the original supported schema/status, all nine fresh string bindings, fresh proof decision, then exact proof scope. Unrelated claimed fields remain unrelated; altered scope remains a refusal. Bit 512 can combine with bit 256 only on action 2, where A must be genuinely fresh unknown and outcome metadata must be zero. Actions 0 and 1 cannot use bit 512. Existing accepted inputs and results in the earlier flag domains remain unchanged.

The full six-tail frame may exceed the old public parent's 128 MiB input scratch. Its maximum paired fresh/claimed JSON-plus-arena footprint approaches 288 MiB plus the fixed header. The caller must reserve a sufficiently large independent span from actual lengths, without overlapping source, output, metadata or workspace; it must not merely raise the extent of the old physical buffer. The pure receipt workspace remains 8 MiB and the return buffer remains 1 MiB. Verification success returns only the fresh result, and large-fresh mode is restricted to unknown results, so this does not expand positive output or action0 authority.

Large qualification includes actual decoding of a 64 MiB claimed document, 20 MiB unrelated claimed strings, complete 16 MiB function strings in both root and subject of fresh/claimed unknown fixtures, original scope/error decisions, and strict one-byte/arena-bound overflows. The fresh unknown fixture comparisons are pure component tests; actual fresh proving in the final unified public owner remains separately required.
