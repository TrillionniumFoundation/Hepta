# Public proof receipt private role ABI

Qualified private receipt component: 391 checks passed against captured actual V8 receipts, the original verification decision policy, actual normalizer diagnostic output, and private protocol/ownership guards. The parent metadata is a private component fixture in these checks. Complete public-process execution, arbitrary public function values, calls, bounded proofs, final installed release and production agent activation remain separate open gates.

## Components

Root owns tools/generate_hia_native_public_proof_receipt.py and examples/hia_bootstrap/native_public_proof_receipt.hepta in native-multiversion-proof-source. The current built candidates are in L/native-public-proof-receipt-v4:
- native_public_proof_receipt.hepta.flat: 490136 B, 7e5d7bfe44592dabaaaa586da498c1d858cf627c2418ed176e74b57be6da76aa
- native_public_proof_json.hepta.flat: 120525 B, f6f3acf8474df795351381aec434de7a3163927953c8365d95dfb32615b6c404

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
- +56 flags: bit1=raw-before hash available; bit2=normalized-before/core hash available; bit4=raw-after; bit8=normalized-after; bit16=whole public image hash; bit32=public source-inventory hash; bit64=use original diagnostic for action1; bit128=disable all canonical/proof claims after deadline/identity/component failure.
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

Public front-end requirements: same immutable raw inputs, same captured/sealed normalizer for admit/diagnostic, verified HIAVCF01 extents/profile, actual SHA hashes of all three byte identities, original before/after error order, one absolute deadline for normalization+private proof+closure. The child V8 relative budget must be floored from remaining nanoseconds; never extend the parent deadline. Before returning a proved/disproved patch, recheck parent wall and whole-image identity; deadline/identity/component failures build unknown and disable claims. Release/caller receipt verification always recomputes.

## Qualification and limitations

The sealed 494833 compiler built the final receipt source (427597 B, SHA256 67de8dd5234fd73c8831cd55f7673f5c5eb14642303088cdcc1c21e022de3d73) and JSON source (92108 B, SHA256 9896f9198d386c363b74b614e7f94bac6c0b17221a7c298bb3427c31a7039bdd). Receipt limits remain 64 functions / 1244 blocks / 7638 operations, within unchanged compiler limits. Complete machine evidence is recorded in HIA_PUBLIC_PROOF_RECEIPT_QUALIFICATION.json.

The private frame deliberately carries a bounded ASCII identifier, with length zero meaning None. An outer public typed-input layer must preserve the original distinction between None and an empty string, and original unknown outcomes/error order for other public function values; these private-frame tests do not close that layer. The diagnostic decoder accepts at most 1 MiB JSON and a 131072-byte message; larger actual producer output must remain an unestablished component failure until a separately qualified complete diagnostic route or exact producer bound is established. No original diagnostic is silently truncated.

The original verification-policy oracle receives a frozen fresh result for these pure-component comparisons; it does not rerun the solver during those decision-policy tests. Actual fresh proof recomputation and all process custody/deadline paths must additionally pass in the enclosing native public service. No caller arena, metadata flag, digest, serialized receipt, or component unit test grants execution authority.
