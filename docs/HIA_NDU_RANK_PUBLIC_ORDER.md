# Native rank public dictionary order

This change restores the original public dictionary insertion order while keeping the existing canonical bytes used for hashes and evaluator requests. The actual original rank function, its proof formatter, and scalar selection function define the common field order.

The implementation adds private action 11 to the existing native rank report role. It does not add a separately loaded role. The rank controller invokes this action only after all fresh validation, proof, evaluator, selection, and cost checks have completed. The original source-bound limits and component budgets remain unchanged.

## Result construction

The final output preserves the original order of the top-level rank result, candidate reports, cost reports, native request rows, selection results, bridge identity, and common scalar proof fields. Each observation uses the insertion order in the actual captured arguments, including all 24 permutations of its four allowed keys. Caller candidate order and observation mapping order remain distinct.

The controller also retains the actual admitted evaluator response bytes before its private canonicalization. The final response is parsed from those actual bytes; canonical response bytes remain the input to binding and selection digests.

The report role validates two fresh captured 72-byte JSON arenas, copies only the final arena, and changes sibling links. Scalars retain their captured lexical bytes. Unknown fields and unknown subtrees keep their existing order. Native-only proof metadata remains present and keeps its existing order after common original fields. No proof value or authority is inferred by the ordering pass.

Key dispatch uses a source-bound table of exact key bytes. Hash lookup is followed by full byte equality, so a hash collision cannot assign a known field's order. The renderer walks validated parent and sibling links without an added nesting limit. Work and output sizes are derived from actual 64-bit arena sizes and node counts.

## Private action 11

Input is the existing HIANRP01 envelope. Its 768-byte header has action 11 at offset 8, mode 0 or 1 at offset 16, and four parts at offset 24. The remaining header words are zero. Four contiguous offset/length pairs start at offset 768, followed by:

1. The completed rank JSON.
2. Its actual fresh arena.
3. The original captured argument JSON.
4. Its actual fresh arena.

Mode 0 measures the complete result; mode 1 writes it. Output starts with the 64-byte HIANPR01 header: required JSON bytes at offset 8, action 11 at offset 16, remaining words zero. Mode 1 writes the JSON at offset 64. Business data is unchanged. Malformed private input returns 0xfffffffd; insufficient output returns 0xfffffffe without writing output. The minimum output extent is 64 bytes.

The workspace requirement is the maximum of:

- 131072 plus the larger of the two actual node counts.
- 16384 plus the final arena byte length plus 16 times its node count.

All additions and multiplications are checked before allocation. This is a storage formula, not an aggregate JSON input limit.

The controller reserves offsets 7040 through 7087 for ordering state. Offsets 7064 and 7072 retain the actual evaluator response pointer and extent. The new phases are 833 through 836. They follow the existing final result construction; original proof and evaluator budgets are not restarted.

## Native construction and qualification

Both changed executable policies were compiled twice by the same captured native source compiler with an empty PATH. The two outputs were byte-identical. Existing bounds remained 128 functions, 1536 total blocks, 256 blocks per function, 8192 operations, 2048 SSA definitions per function, and 16 block parameters. The generated report has 64 functions, 1227 blocks, 5728 operations, at most 181 blocks per function, and at most 1523 definitions per function.

The qualification JSON records all actual source and image hashes and the immutable evidence reports. The completed checks are:

- 357 original report cases, including exact canonical bytes, dynamic strings, private guards, and atomic short-output rejection.
- 72 new ordering cases, including all observation permutations, original proof formatters, exact-key collisions, poisoned workspaces, 9 MiB content, and forged arenas.
- 74 actual native pack, independent layout, and unchanged entry-domain guards.
- 44 complete native rank calls: the original 17 cases, 24 actual observation permutations, and three additional fresh-proof permutations. These include 32 proposals and 72 MiB aggregate argument input.

Each complete product call was one actual sealed native engine invocation. The reference ran the original rank function against recorded actual clock samples and actual fresh native proof outcomes, preserving the prior semantic differential method. It additionally compared every public dictionary recursively in insertion order. The common proof order was derived separately from the original proof constructor and scope formatter; it was not accepted merely because the canonical native callback had that order.

Development failures are preserved: an early report generator exceeded the unchanged compiler profile, and another placed too many blocks in one function. Splitting fixed key-priority helpers resolved those construction failures without enlarging any limit.

## Scope

This qualification closes public result ordering for the tested native rank engine composition. It does not declare the final asynchronous cancellation composition, public owned-result lifetime, BackgroundOptimizer, multiversion runtime, or whole release complete. The cancellation work is independently owned and must be combined with these two policies before its final interaction checks. Python files here are development authors and qualification oracles; native execution uses the generated HIA policies and existing native packer.
