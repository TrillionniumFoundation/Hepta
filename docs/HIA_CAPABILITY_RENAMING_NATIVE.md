# Native Core capability edge renaming

`capability_renaming.hepta` implements the complete graph-renaming policy used
by the production Core CFG checker: injective target names, present sources,
survival of every local owner/loan, root and parent closure, and exact transport
of type, external status and original function-parameter identity. External
capabilities not selected by an edge may be forgotten. Cycles and unusual
root/parent relationships are transported exactly as the existing edge policy;
the surrounding Core verifier remains responsible for constructing valid
capabilities, join compatibility, borrow permissions and return obligations.

This is one actual verifier component, **not the general native Core verifier**.
The Lean model in `formal/HiaCapabilityRenaming.lean` specifies relational
properties, not a refinement proof for this native program or its host bridge.

## Explicit selection and authority

Build with `python -m tools.build_hia_capability_renaming --compiler <B3>
--cold-report <cold.json> --output <new-directory>`. Select its local manifest
using `HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST`. The default is unchanged.
A selected broken artifact or refused graph fails; there is no selected-path
fallback to `_reference_rename_capabilities`.

The host captures verifier-owned exact dictionaries and frozen `Capability`
records, interns opaque exact strings, encodes unsigned rows, allocates private
buffers and reconstructs Python records. It does **not** resolve graph edges or
compute injectivity/liveness/closure. Symbol interning, JSON/object admission,
the remaining verifier, executable custody and build/installation still depend
on the host. Native output is never a general Core safety receipt. Unsupported
or forged record field types fail closed on the native route; the supported
production records have exact strings, optional strings and Boolean flags.

## Full internal transport

`HIACAP01` has eight little-endian u64 header words: magic, capability count,
edge count, symbol count, and four zeros. Each capability has six u64 words:
name, type, root, optional parent, external flag, optional origin. Each edge
has source and target symbol IDs. `2**64-1` is the absent optional ID. HIA
validates every record and consumes exactly the framed byte count. It computes
all source/target/graph relations using three private symbol-indexed tables.

Counts permit the entire general Core ceiling of 262,144 capabilities and
262,144 edge entries, with up to 2,097,152 opaque symbols. The fact frame is at
most 16,777,280 bytes. Result space is `64 + 48*edges` bytes and scratch is
`result_space + 24*symbols`; this is internal transport, not an increase to the
existing 8 MiB Core JSON, 262,144-node, depth-64 admission profile.

`HIACAR01` has eight words: magic, edge count, symbol count and five zeros;
then six-word renamed records in input edge order. All policy checks finish
before any public output byte changes. Native failures distinguish malformed
transport, insufficient buffers, duplicate targets, absent sources, dropped
locals and missing root/parent closure. The latter retains `E_HIA_LOAN`; other
policy failures retain `E_HIA_RESOURCE` and the existing diagnostic precedence.

## Verification

Tests interpret independent complete packet/result bytes in the ordinary Core
VM before building a seed/image. Actual native tests cover all field relations,
permutations, 400 random nested graphs and edge composition, exact refusal
messages/precedence, private concurrent calls, source-bound cache refusals and
real production CFG execution with the foreign edge policy forbidden. A full
262,144-capability reversal and one-past refusal retain the real node ceiling.
These are bounded executable witnesses, not all-input correctness proof or
whole-product/native-only installation acceptance.
