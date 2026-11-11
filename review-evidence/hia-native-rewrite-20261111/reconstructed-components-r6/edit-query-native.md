# Native complete edit-query construction and bounded wire

This is development evidence for new HIA owners, not a native-only release.
The public capture, admission, orchestration, apply and batch paths remain open.
No active hosted owner can be retired on the strength of these components alone.

## Query packet owner

`agent_edit_query_packet.hiaasm` constructs the entire existing v2/v3 edit
query from an immutable admitted source, actual native facts and slice output,
and actual canonical base/input/operation digests. It preserves declarations,
operation indices, dependent and consuming instructions, downstream CFG views,
sorted affected names, call signatures, default returned-loan origins, selected
field ordering and the original scope text. Source-order callees are discovered
with exact name comparison; a digest never substitutes for identity equality.

Its RWW entry is `(command, SourceIndexLease, workspace)`. The command contains
sixteen u64 words, three 32-byte digests, 32 reserved zero bytes, then the complete
facts and slice packets. Words are magic `HIAQQC01`, action BEGIN=1/CONTINUE=2,
lease, request, sequence, facts length, slice length, function/block/instruction
references, block index, instruction index, field mask, and three zero words.
The field mask is args=1, attrs=2, op=4. The second buffer is borrowed read-only
inside the fixed wrapper; it cannot be caller-writable during the operation.

A fresh workspace has at least 1024 zero bytes. An ordinary return of 384
publishes sixteen words at offset 256: `HIAQQE01`, action DONE=0/GROW=1,
lease, request, next sequence, required workspace, output offset, output length,
error and seven zeros. GROW retains every prior byte and uses the same immutable
source/facts/slice/digests. ABI failure returns `0xfffffffd` and permanently
poisons the session when the state fits. Completed sessions cannot be reused.
Headers alone do not authenticate any input; the final fixed driver must retain
the actual issuers and successful whole-program admission in its call chain.

The frozen source is 146067 bytes with 53 functions, 539 blocks, at most 94
blocks per function, 2277 operations and 11 block parameters. Its SHA-256 is
`2588627d9aa3ab44367c8b5ccbf580243f70f8e7c87a3cf727355c9e2648890a`.
The actual qualified B3 produced image
`c490682e7e0e2e1c508371c906976f7e879defac7c26dc0dd749d6b505ddcf0c`.
All original compiler limits were retained.

The independent VM control preceded compilation. The actual issuer → facts →
slice → operation/program canonicalization and SHA → query → issuer → canonical
wire and SHA pipeline then produced 99 complete queries equal to the retained
interface, with three expected native slice-budget refusals. It used 309 query,
204 facts and 399 issuer entries. Seven private protocol controls also passed.
Old query construction, slicing, fact encoding and object decoding were disabled
during the actual forwarding interval. Original source snapshots, full buffers,
canaries, compile receipts and failure attempts are retained. The first authoring
attempt failed before generation because the authoring builder did not implement
division; its original source and error were not relabelled as a passing run.

## Full bounded JSON integration

`packet_graph.hiaasm` converts an actually issued integer typed tree into the
general GraphLease used by the complete bounded JSON wire owner. HIA counts
nodes and edges, allocates by a checked GROW request, builds exact child IDs,
copies strings, counts their validated Unicode code points and converts every
decimal integer into minimal little-endian magnitude. This is a private tree
bridge. It does not claim to capture arbitrary foreign objects, aliases or
cycles; those enter the separate general GraphLease owner.

Its RWW entry is `(SourceIndexLease, command, workspace)`. The 64-byte command is
`[HIAPGC01, action, lease, request, sequence, 0, 0, 0]`. A fresh workspace has at
least 512 zero bytes. The sixteen-word event at offset 256 is
`[HIAPGE01, action, lease, request, nextSequence, neededWorkspace, graphOffset,
graphBytes, error, nodeCount, edgeCount, scalarBytes, 0, 0, 0, 0]`.
Return, GROW, immutable-lease and permanent-poison rules match the query owner.
No new public quota is introduced by the internal table sizing.

The final bridge source is
`19b811929d7b40541c482a49e2cbdffa3fa7240e48fa1a8dce5161a0403bc071`,
and its actual B3 image is
`c173c6cfc43beebe97ca6e295b9618e7a791064ea47f9305307a90465561122b`.
An empty integer magnitude still carries a valid cursor within the scalar pool;
its length and sign are zero. The first bridge used offset zero for integer zero
and the actual wire owner correctly refused it with ABI reason 13. Both the
original failed integration and the corrected source/compilation are retained.

The corrected actual issuer → bridge → Graph wire scan/emit → SHA chain passed
130 cases, including all 99 earlier complete queries, integer and Unicode trees,
exact/one-byte boundaries and nesting boundaries. Eight private protocol
controls passed, and three cases compared the full native workspace with the
independent VM. There were 283 bridge entries, 130 issuer entries, 233 scan
entries and 366 emit entries. Every accepted wire and digest matched the old
bounded interface; semantic refusals matched its original first error.

These results close the complete query payload and bounded wire component
calculation. They do not replace the original whole-program admission, establish
public capture resource bounds, authorize response fields, reverify a candidate,
provide durable Agent state, or qualify a new combined production source.
