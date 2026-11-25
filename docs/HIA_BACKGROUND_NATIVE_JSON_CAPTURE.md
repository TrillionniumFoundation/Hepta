# Native owned JSON capture for BackgroundOptimizer and rank arguments

This component captures JSON-owned values for the native typed adapters. It is a separate profile from the strict Core, proof, receipt and evaluator JSON decoders. Its successful result is a fresh owned arena; it does not establish any proof, runtime, evaluator, or publication authority.

## Interface

The entry is a six-word HIA function over disjoint source, output and workspace views. Source contains the complete raw value encoding. All lengths, raw offsets, key scopes and arena offsets are unsigned 64-bit words.

The caller first sets workspace word 104 to zero, supplies at least 128 workspace bytes and 64 output bytes, and calls the entry. Return zero produces the 64-byte HIANJS01 sizing record:

| Offset | Meaning |
| --- | --- |
| 8 | Conservative number of nodes |
| 16 | Conservative number of keys |
| 24 | Maximum scanned nesting depth |
| 32 | Required arena allocation |
| 40 | Required workspace allocation |
| 48 | Actual source length |
| 56 | Zero |

Sizing is not syntax admission. It can succeed for malformed input. The caller allocates the returned extents, sets workspace words 48, 56 and 96 to the returned node, depth and key bounds, sets word 104 to one, and calls again. Only return zero from this second call establishes a valid arena.

The result uses the existing 64-byte header and 72-byte records. The complete used length is the full word at header offset 24, not the function's u32 return. Record kinds are null, false, true, number lexeme, string, array and object. Raw numeric spans retain the exact original lexeme. Strings and keys are stored in the arena. Original raw bytes remain unchanged. The caller must retain the matching raw bytes and arena together.

Repeated keys are normalized to Python dict semantics: the last value wins, while the key keeps its first insertion position. Overwritten subtrees are removed. Final node IDs are compact, parents precede children, and sibling traversal preserves insertion order. Sizing may therefore overestimate the retained node count.

Unused scalar record words at offsets 56 and 64 are explicitly zeroed. The older strict decoder can leave parser scratch values in these undefined words. Qualification compares every defined byte with that decoder and checks the new unused words are zero; it does not claim identity of undefined scratch contents.

## Value domain and responsibilities

This owned-value profile retains escaped or raw lone surrogates in WTF-8, recognizes NaN and positive or negative Infinity lexemes, and combines a valid escaped surrogate pair as JSON does. It preserves duplicate key semantics rather than applying the strict receipt/Core duplicate-key rejection.

The component has no aggregate 8 MiB limit, fixed node-count ceiling, or fixed nesting-depth ceiling. Actual capacities are derived from source size with overflow checks. Qualification includes a 96 MiB frame and more than one million nodes. Original per-Core, submit, evaluator, proof and publication limits remain in their existing owners.

This component performs lexical typed capture. It does not convert a decimal token into a host integer or enforce the interpreter's integer-to-string conversion policy. The checked freezer and structure owner apply the actual captured conversion policy at the original conversion points; production callers must not accept a request-supplied zero to bypass the default policy. The comparison oracle disables only its decimal parse limit to recover the lexical integer value, then applies the actual 4300-digit conversion policy in the separate freezer comparison.

The JSON-owned representation cannot express foreign Python classes, cycles, or non-string dict keys. Those remain the public typed ingress's responsibility. Malformed JSON produces a native rejection status, not a CPython JSONDecodeError message. The strict JSON diagnostic component is independently responsible for exact original error text and positions where the original API exposes them.

Return FFFFFFFD denotes a private framing/dispatch/capacity error, with additional existing decoder rejection statuses for malformed input. The minimum-view and invalid-dispatch gates reject without modifying the output. A malformed value or an inconsistent second-pass capacity does not promise an atomic usable arena; consumers must ignore all arena bytes unless that second call returns zero.

## Construction and evidence

The source is compiled twice through the sealed native source compiler. Both outputs are identical. No target compiler, Python parser or Python JSON operation participates in product execution; Python is used only by the development author and independent comparison harnesses.

The qualification index beside this document records complete source, compiler, flat and report hashes. The final product is 212039 bytes with SHA256 62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f.

The accepted evidence comprises:

- 782 fresh original-value/type/order comparisons and actual checked-freezer combinations, including 368 defined-byte strict-profile comparisons, lone surrogates, nonfinite values, repeated keys, integer conversion policy, depth 600, 1,048,578 nodes, 100,000 repeated keys, a 96 MiB frame and overwritten values larger than 8 MiB.
- 45 actual native helper controls with sparse source and workspace views spanning 2^32, including offsets, Unicode decoding, key equality, full-width scope values, and the new duplicate-compaction copy/hash paths. This does not claim that a whole 4 GiB document was scanned.
- 27 exact minimum-view, invalid-control, canary, unchanged-source and atomic-refusal controls against the actual product flat.

Earlier failed observations are preserved: the original comparator incorrectly compared undefined scalar scratch words, and its recursive equality helper exceeded the Python stack at depth 600 even though both original json.loads and native decoding succeeded. The final comparator is iterative and compares all defined fields without relaxing value, order, syntax or business-policy expectations.

This is component qualification. The complete BackgroundOptimizer and native rank owner require their own actual provider, identity, worker, cancellation, accounting and publication evidence.
