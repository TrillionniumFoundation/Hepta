# Native edit entry prefixes and exact snapshot comparison

These private HIA owners preserve the retained edit entry points' validation
order. They operate on issued immutable Graphs and admitted canonical Core
views. They do not establish arbitrary Python foreign-object lookup semantics,
program admission, or a production public coordinator on their own.

## Ordered input prefix

agent_edit_input_graph.hiaasm has three modes. Single apply first requires an
exact query dictionary and an exact three-field selector. Batch prepare checks
the list size, then only the requested current selection. The caller must finish
that selection's query and overlap check before requesting the next one.
Batch apply receives the already bounded, integer-decoded query and checks every
ordered site and every nested selector before reconstructing any query.

Each successful record contains four actual Graph node IDs for function, block,
output and fields. A missing fields node is represented by zero; the selector
owner then emits the original fields refusal before checking identity kinds.
The other three identities must have issued nonzero nodes. No hosted key lookup
or schema selection occurs in these owners.

RWW entry buffers are Graph, 128-byte command borrowed read-only, and 1,024-byte
zero workspace. The command is:

    [HIAQIC01, mode, lease, request, root, currentIndex, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

The sixteen-u64 event at offset 256 returns 384:

    [HIAQIE01, action, lease, request, mode, totalCount, currentIndex,
     512, rootsBytes, error, emittedCount, 0, 0, 0, 0, 0]

Action 0 is success, 2 semantic refusal and 3 private protocol failure. At most
16 four-u64 records fit at offset 512. A private failure poisons its invocation;
short workspaces are discarded. The complete immutable Graph belongs to the
fixed issuer throughout the call.

The original source is 44,934 bytes, SHA-256
9882cc3aaec50afbd92cd67fd0dfacbe640ff4ae3715557706d3f565ce4146a6;
the actual B3 image is ad04d1bf1852551e28a1a07be6c3204d6e4c729975b0297bcb3c8dde11cabf59.
It has 19 functions, 209 blocks, 702 operations, at most 48 blocks per function
and 8 block parameters. Eight independent VM cases preceded actual compilation.

Native r1's oracle wrongly passed a decoded string as raw syntax and failed
after 53 completed prefixes; that original remains retained. Native r2 corrected
only this prerequisite representation and passed 85 prefixes, 12 complete query
reconstruction chains and 8 private controls in 4.160599656 seconds. It made 134
prefix, 64 selector, 41 batch and 44 merge entries, with 31 actual native queries.
Cases retain early overlap before a later malformed selection and all nested
shape checks before any batch-apply reconstruction. Hosted semantic and JSON
owners were disabled during actual execution. This is development evidence.

## Exact reconstructed-query bytes

agent_edit_match_wire.hiaasm receives the two actual canonical wire views and a
512-byte workspace. It compares complete lengths and bytes, keeping true, 1 and
1.0 distinct. Its original maximum is 1 MiB for each already canonical view.
Neither a digest nor container equality substitutes for the comparison.

The first 64 workspace bytes contain:

    [HIAQMC01, mode, lease, request, 0, 0, 0, 0]

All remaining initial workspace bytes must be zero. Mode 1 emits the original
single stale-query text; mode 2 emits the original batch stale-query text.
The sixteen-u64 event at offset 128 returns 256:

    [HIAQME01, action, lease, request, mode, leftBytes, rightBytes,
     privateReason, diagnosticOffset, diagnosticBytes, 0, 0, 0, 0, 0, 0]

Action 0 matches and action 2 rejects with complete HIA-owned text at offset
256. Private failure returns BAD permanently. Completed calls cannot be reused.

This source is 15,175 bytes, SHA-256
77e9727a3b0532ace68113e6f39c8f5bfe61455c4a9ac89870370b25f32b60f7;
its actual image is 01883031e2b5fbb998d64fabe093e45da5ece1911e9705e2b5ace5322f73adfc.
It has 7 functions, 56 blocks, 274 operations, at most 37 blocks per function
and 6 block parameters. Eight independent VM cases preceded actual compilation.
Native r1 passed 56 comparisons and 21 private controls, making 92 actual entries
in 0.510900089 seconds. Whole-workspace VM pairs, all inputs and boundary canaries
were checked. Exact 1 MiB matches and first/middle/last byte differences are kept.

Both owners use the actual unchanged 35ee92b7... B3 under the original 1 MiB,
10 CPU second, 20 wall second and 256 MiB compiler gates. No complete retained
regression, cold or whole-stack claim follows from these component results.
