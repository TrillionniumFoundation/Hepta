# Native edit application and ordered batch construction

These new HIA components own the complete response-policy, patch-construction
and batch-construction calculations described below. Their public selection,
query reconstruction, first-error capture/decode sequence and fixed executable
coordinator remain in progress. They do not yet permit retiring the hosted
public interfaces or claiming a native-only release.

## General immutable Graph composition

`graph_merge.hiaasm` joins two privately issued immutable GraphLeases under a
new list root. It rebases all nodes, edges and scalar pointers without decoding
payload values on the host. It preserves exact scalar kinds and bits, tuple/list
distinctions, insertion order, nonfinite values, surrogates, unsupported kinds,
bytes, aliases and cycles within each source. Cross-lease identity is not inferred.
The caller may select any valid root in each source. Containers receive unique
rebased identities; all original alias/back edges retain their targets.

The RWW inputs are a 128-byte command followed by Graph A, Graph B, and a fresh
512-byte workspace. Command words are `HIAGMC01`, BEGIN=1/CONTINUE=2, new lease,
request, sequence, selected A root, selected B root, and nine zero words.
The event at offset 256 returns 384 and contains `HIAGME01`, DONE=0/GROW=1,
lease, request, next sequence, required workspace, graph offset, graph length,
error, node count, edge count, scalar bytes, new A root, new B root and two zeros.
GROW preserves the whole workspace and immutable sources. A private ABI failure
returns `0xfffffffd` and poisons the session. Done sessions cannot be replayed.

Frozen source/image SHA-256:

| Component | Source | Actual image |
| --- | --- | --- |
| Graph merge | `e2c9bc7fe841c628a9bcc492f48bed02e468ce699250c6d223f4eba0a894dbca` | `e7915e121cd863dee54fc43ce03e219a4de7ca3ad5f8aa7a004dbef05fcb554a` |
| Apply Graph | `a61d2bcbb23e82db341eca47fac6ca4d4d132018bac82bf1c600cad1c2d5e5e6` | `19894fab721624914ed066293a4b715951d99d15df0c32ed4c2e32e09525b4bc` |
| Batch Graph | `49e548a8cdbe6c98bd66bac28149c25e875ec12f603cb2d92ae7d86b7c7aaa6f` | `97786a9c7fd80572d11ed211937cd71622ccf5f30972f3aa8df0fab24355b435` |

All three were independently interpreted before actual compilation by the
published 0ef B3 (`35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b`).
The original 128-function, 1536-block, 256-block-per-function, 8192-operation,
16-block-parameter and compiler execution/buffer limits were unchanged.

The actual merger passed 41 cases and eight private controls. Every entire
result Graph matched an independent byte-level oracle. Three cases compared
complete VM/native workspaces. Native bounded wire then agreed on bytes or the
first semantic error. There were 99 merge entries and 71 scan/101 emit entries.
The general Graph input capture in this isolated test is explicitly a reference
fixture, not proof of public native foreign-object capture.

## Single and batch response application

`agent_edit_apply_graph.hiaasm` takes one immutable composite Graph containing
the admitted original, the actual reconstructed query and the normalized
decoded response. Its 192-byte command has sixteen u64 words followed by native
query/response SHA-256 digests. Words are `HIAQAC01`, action, lease, request,
sequence, mode (single=1/batch=2), base/query/response root IDs, original response
wire length and six zeros. The response-byte prerequisites retain 16384/65536
bytes respectively. This check is an internal invocation check: it does not
replace the public gate's original ordering or diagnostic.

The owner validates the entire response before constructing any patch. A single
response must be a nonempty exact map whose keys are selected fields. A batch
response must contain exactly `edits`; every selected site occurs exactly once,
with exact integer site identity, exact `{site, changes}` shape and nonempty
authorized changes. Duplicate, negative, out-of-range and boolean site IDs are
refused. Changes replace only existing selected operation fields. Outputs and
all other interface fields retain their original nodes. Batch replacement order
is the response edit order. There is one complete patch, with no admission of
intermediate candidates.

The result Graph contains `[patchEnvelope, pendingReceiptMetadata]`.
`patchEnvelope` is `[original, patch]` with the existing v1 patch contract,
expected canonical base digest and complete replacement operations. The pending
metadata has the exact existing edit-query/edit-batch receipt fields, canonical
query SHA and original response wire length/SHA. It is private pending data.
The driver must not expose it until the original patch image and complete Core
image have admitted the final candidate. These components do not make a header,
digest or claimed boolean into an admission certificate.

An ordinary result returns 384 and publishes at offset 256:
`[HIAQAE01, action, lease, request, nextSequence, neededWorkspace, graphOffset,
graphBytes, error, resultRoot, patchEnvelopeRoot, pendingMetadataRoot, mode, 0, 0, 0]`.
Actions are DONE=0, GROW=1 and semantic refusal=2. Private ABI failure returns
`0xfffffffd` with permanent poison. Fresh workspaces require 1024 zero bytes.
GROW pins the complete immutable command (including both digests) and source.

The full actual development chain used the general native JSON decoder and
arena-to-Graph bridge, native Graph merge, apply owner, bounded wire, native SHA,
native patch image and complete Core admission. Its 122 cases comprise 106
exact accepted patch/candidate/metadata results, 13 exact response-policy
refusals and three invalid candidates with the matching Core error category.
The latter is a category comparison, not a claim that every historical detailed
diagnostic string is identical. Eight private controls passed. There were 248
apply, 488 merge, 366 JSON decoder, 732 arena bridge, 674 scan and 1011 emit
entries. Old verifier, edit, patch and object-decoding semantic owners were
disabled in the actual forwarding interval. Source/image pins were unchanged.

The frozen apply profile is 32 functions, 392 blocks, at most 83 blocks in a
function, 1700 operations and at most 16 block parameters.

## Complete batch construction and error ordering

`agent_edit_batch_graph.hiaasm` consumes the ordered root IDs of actual native
single queries bound to the same admitted base/input snapshot. The fixed driver
must call PREFIX immediately after each single query, before preparing the next
selection. This preserves the original observable order: an overlap at the
second site wins over an invalid selector at the third. Two outputs of one
multi-result instruction still identify one site. Matching function, block and
instruction index is an overlap; output-name equality is insufficient.

The 128-byte command plus root-ID vector is
`[HIAQBC01, action, lease, request, sequence, finalFlag, count, 0...0] + roots`.
The original 1..16 site range remains. PREFIX (`finalFlag=0`) returns success
without a result Graph; FINAL (`finalFlag=1`) constructs the complete existing
v2/v3 batch query with ordered site identities, base/input digests, application
and scope fields. The complete bounded wire gate follows construction and may
refuse the combined query; no subset is silently retained.

The event is
`[HIAQBE01, action, lease, request, nextSequence, neededWorkspace, graphOffset,
graphBytes, error, batchRoot, count, finalFlag, 0, 0, 0, 0]`.
Workspace, return, growth and permanent-poison rules match Apply Graph.
Mixing privately supplied queries from different source/schema identities is
an ABI failure. This is separate from the public stale-query check, which must
compare actual reconstructed canonical wire before any response is consumed.

The frozen batch profile is 28 functions, 356 blocks, at most 84 blocks per
function, 1605 operations and at most 16 block parameters. Seven actual end-to-end
groups made 27 fresh native single queries and checked each prefix before
continuation. They covered one/16 sites, the simultaneous two-loan swap, reversed
selection/response order, repeated output, multi-result aliases and overlap
before a later invalid selector. Four groups continued through the actual apply,
patch and complete final admission owners and matched candidate plus metadata.
Eight private controls also passed. The forwarding path disabled the original
semantic owners. These are development results, not a combined public release
qualification or a substitute for the retained full regression/cold gates.
