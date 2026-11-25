# Native public proof typed arguments

This is a pair of private six-word HIA components. The public owner derives their inputs from actual values or from its own freshly decoded JSON; an external caller cannot provide a verified arena, type tag, node identity, or proof result. These components do not execute a proof. Their current component qualification does not close the whole public API.

## `public_proof_typed`

Input `HIAPTV01` is 64 bytes plus a string classification probe. All words are unsigned little-endian u64:

| Offset | Meaning |
| --- | --- |
| 0 | `HIAPTV01` |
| 8 | Fixed API timeout maximum, 1 through 60000 |
| 16 | Timeout kind: 0 exact nonnegative integer in u64; 1 exact negative integer with u64 magnitude; 2 exact integer outside u64 magnitude; 3 every other actual type |
| 24 | Integer magnitude for kinds 0 and 1 |
| 32 | Opaque original timeout value handle |
| 40 | Function kind: 0 None; 1 exact string; 2 every other actual type |
| 48 | Opaque original function value handle |
| 56 | String probe byte count; zero unless kind 1 |
| 64 | Probe bytes |

The native value caller derives exact tags without invoking conversion methods. In particular bool, float, str and integer subclasses are not exact integers; string subclasses are not exact strings. Handles are only returned and are never dereferenced. A full string may be supplied; a JSON adapter may supply its first 129 decoded bytes when the original decoded string is longer than 128, because every such string is outside the selector grammar. The original complete value remains bound to its node/handle.

Output `HIAPTR01` is 96 bytes plus at most 128 ASCII selector bytes. Words are: magic; timeout-valid flag; accepted budget or zero; original timeout handle; selector class (0 None, 1 valid ASCII identifier, 2 invalid exact string, 3 non-string); original function handle; selector byte count; original timeout kind; original function kind; three zero words. The selector tail is present only for class 1. Output capacity is checked before any write. Failure is u32 `0xfffffffd`.

## `public_proof_values`

The input `HIAJPV01` is a 256-byte header followed by at most three `(JSON bytes, wire-spans arena)` pairs. Both pieces come from the same actual decoder invocation. It validates arena extents, node kinds, parent/sibling/child ownership, raw spans, selected node indices, and every output extent. It does not replace the decoder or trust externally supplied arenas. Workspace is 262144 bytes; the first role needs no workspace.

| Offset | Meaning |
| --- | --- |
| 0 | `HIAJPV01` |
| 8 | Action: 0 classify values, 1 rebind fresh unknown receipt, 2 select a verification function |
| 16 | Fixed timeout maximum |
| 24 | Fixed exact-integer default timeout, 1 through the maximum |
| 32 | Action 1 flags: bit 0 replace function, bit 1 replace timeout; other actions require zero |
| 40, 48 | Function document index and node index |
| 56, 64 | Timeout document index and node index |
| 72, 80 | Receipt document index and node index |
| 88 | Opaque original function handle |
| 96 | Opaque original timeout handle |
| 104 | Document count, 0 through 3 |
| 112, 120 | Zero |
| 128, 136 | Document 0 JSON byte count and arena byte count |
| 144, 152 | Document 1 JSON byte count and arena byte count |
| 160, 168 | Document 2 JSON byte count and arena byte count |
| 176 through 248 | Zero |

An absent reference is `(UINT64_MAX, UINT64_MAX)`. Missing function is None; missing timeout is the fixed default. Every unused pair length is zero. Used pairs are nonempty, exact EOF is required, and the wire-spans arena uses the same 64-byte header / 72-byte nodes as `native_public_proof_json` (at most 131073 nodes). Both references must be valid even if an action does not use a particular value.

Action 0 outputs a complete `HIAPTV01` request, at most 193 bytes. It distinguishes integer tokens from fraction/exponent numbers and bools, checks u64 overflow without coercion, preserves negative zero as integer zero, and classifies decoded strings. Its output is then passed to `public_proof_typed`.

Action 1 requires a complete fresh receipt object at node 0 with status `unknown`. It replaces exactly root `function` and `subject.function` when bit 0 is set, and `solver.timeout_ms` plus an already present root `timeout_ms` when bit 1 is set. No top-level timeout field is added when absent. Replacements use complete original raw JSON value spans, including the original string escaping. Missing function emits null; missing timeout emits the exact default integer. All other original receipt bytes are retained. Every patch is checked for overlap and capacity before output writes. A positive or disproved receipt cannot enter this path. Output is the complete JSON byte sequence, without a new envelope; the parent updates its existing HIAMVR01 JSON extent. The output buffer must hold the actual complete result, with no truncation. The role does not alter claims, identities, hashes, wall time, or schema.

Action 2 first checks the claimed receipt is an object with translation schema and status `proved`. It then selects the explicit function unless that value is None/missing, in which case it takes `receipt.function` including an arbitrary typed value. It does not reject a non-string before fresh proof. Output is a 64-byte `HIAJPS01`: magic; supported flag; selected document; selected node; raw JSON offset within that document; raw value byte count; whether receipt fallback was used; zero. Unsupported receipts have supported=0 and absent selected references. This performs only the original initial receipt/selection step; the existing receipt role still performs fresh proof, binding, decision, and scope checks in order.

## Primitive invalid selectors and call selectors

The original verifier rejects the seven reserved function definitions `abort`, `calloc`, `malloc`, `free`, `memcpy`, `memmove`, and `memset` in every accepted Core schema. `_function` in `hepta/hia_program.py` calls `_ident` and then rejects `_RESERVED_FUNCTIONS`; `_ident` also reserves the `__hia_` prefix. The private primitive owner can therefore use the fixed selector `abort` for an invalid typed function, then restore the original function value in the fresh unknown receipt. This preserves actual Core/schema/selection/profile ordering and cannot enter a solver. None continues to use name length zero and the original inference rule. No MVP03 or new primitive flag is introduced. The separate call owner requires an explicit function and uses name length zero for invalid/None values, without inference.

The JSON span route covers values expressible in its actual JSON decoder. The opaque value route preserves non-JSON object identity, cycles, subclasses and invalid Unicode string values without serialization or coercion. Neither component alone is evidence that a public value adapter or the complete MV integration is finished.

## Embedded owner continuation

`tools/hia_public_proof_typed_flow.py::SOURCE` is a development authoring helper to embed in the final owner, with no additional runtime role. `public_typed_choice(w, result_offset, result_size, call_profile, target_offset)` reads the actual HIAPTR01, checks its extent, reserved words, identifier grammar, type/class consistency and profile budget, and writes only after every check. `call_profile` is true only for the call API. The result and the 192-byte target area must be disjoint and owned. The target words are budget, name extent, rebind flags, function handle, timeout handle, selector class, budget-valid flag, zero; the selector tail starts at +64. Unknown typed function uses abort for primitive and an empty selector for calls; None retains each API's original behavior. Invalid typed timeout becomes private budget zero and rebind flag 2, so the original type refusal happens before normalization. Valid exact values pass through.

The JSON owner order is: actual options/claim decode; for verification only, action 2 receipt support/selection; values action 0; classifier; embedded choice; actual public normalization/proof; decode actual fresh unknown if choice flags require rebinding; values action 1; for verification, existing receipt action 2 performs the fresh nine bindings/decision/scope checks. No prior receipt authorizes proof execution. Whole normalization/proof deadline, cancellation and image custody remain the public owner's responsibilities.
