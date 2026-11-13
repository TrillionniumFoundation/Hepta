# Native enum-match lowering

`HEPTA_HIA_ENUM_MATCH_MANIFEST` explicitly selects the HIA implementation of
the complete `match` terminator responsibility in the ordinary nominal
elaborator. The operator-owned manifest binds
`examples/hia_bootstrap/enum_match.hiaasm`, its native image and its compiler
digest. Submitted program bytes cannot choose this manifest. Selection failure,
source mismatch, transport failure and semantic refusal never invoke the
retained reference match implementation.

The HIA owner validates match/case fields, source names and case arguments,
exhaustiveness, duplicate cases and the prohibition against carrying a matched
linear enum on its own case edge. It performs block lookup, nominal/primitive
target-type comparison, duplicate linear-transfer checks and live-value
preservation. It builds the deduplicated primitive carry inventory in the
original environment order, excludes selected aliases from inactive padding,
drops inactive owners, rejects inactive loans and emits the entire decision
CFG, including the invalid-discriminant trap. Every generated name and the
final fresh-name counter belong to HIA, including the counter after refusal.

The bridge returns a complete Core first-block suffix and complete additional
blocks. It does not interpret a lowering plan, look up cases, decide liveness,
compute target types or create instructions. The ordinary caller copies those
objects into the surrounding function. The complete primitive verifier still
checks the result. This does not move ordinary record/enum construction, other
operations, source/type admission, function orchestration, returned-loan entry
binding, exports, the Agent, persistence or installation into this owner.
Composite v1 still produces primitive v6, v2/v3 produce v7, and v4 produces v8.

## Descriptor and identity custody

The private packet is a typed, length-delimited tree:

```text
[serial, source_term, descriptors, environment, block_signatures]
descriptor = [kind, primitive_flat_types, linear, [[variant, field_type_ids], ...]]
environment_entry = [source_name, type_id, primitive_names, external, consumed]
block_signature = [source_block_name, parameter_type_ids]
```

Both retained type owners intern every nominal descriptor within one
elaboration: the hosted `_Types.cache` and the native session's HIA-issued
descriptor graph. The adapter preserves that graph by Python object identity
while holding every descriptor alive for the packet. It does not call Python
type equality or hash a nominal identity. The HIA kernel compares nominal
descriptor IDs directly. Primitive descriptors can be materialized separately;
HIA compares their transported primitive names. No exponentially expanded
nominal display key, object address or session token enters normalized Core.
The packet is an internal representation of already admitted descriptors,
not an alternate public type declaration interface. Mixing unrelated type
sessions or inventing nominal descriptors does not acquire source admission.

The image validates the private graph's representation before using it:
descriptor and reference ranges, exact field inventories, primitive names,
boolean flags, enum-flat/variant correspondence, buffer extents and safe output
names. This does not replace the preceding type owner or decide source type
declarations a second time. Source term checks and their first-error ordering
remain the semantic responsibility of the match image.

## Private bounds preserve the public profile

The public document retains 8 MiB, 262,144 JSON value nodes and depth 64.
Nominal elaboration retains 128 completed/active instantiations, 512 primitive
slots per nominal layout, 32 enum variants, 64 fields per variant, 32,768
elaborated value slots and 8,192 generated names. None of these limits is
reduced by native selection.

The private typed input allows 256 MiB, 8,388,608 nodes and depth 128. These
are representation allowances, not larger public input limits. The private
tree does not recursively expand record graphs: variants refer to descriptor
IDs. A conservative node calculation uses `N = 262144`, `V = 32768`, and
`D <= V + 128*511 + 128 = 98304` distinct held descriptors. Primitive
descriptors used by environments/signatures consume the original value-slot
budget; a retained enum's primitive field descriptors consume its 511
non-tag slots. Zero-width nominal types remain interned and add no new
primitive descriptor per source occurrence.

| Packet part | Conservative typed-node bound |
| --- | ---: |
| Raw source term, including object keys | `2*N` |
| Environment tuples and primitive names | `6*N + V` |
| Block-signature tuples and parameters | `3*4096 + N` |
| Descriptor graphs, flat arrays and variant fields | `6*D + 128*512 + 128*32*3 + 128*32*64` |
| Root and inventory containers | `8` |
| Total | `3,334,152` |

This is below 8,388,608. Even charging 24 bytes per typed node, all copied
128-byte environment/primitive/block/variant names, and the complete original
8-MiB source-term text stays below 140 MiB; the 256-MiB allowance has additional
room. The descriptor tree has at most seven container levels. A source term
loses its original function/block ancestors when put in the packet, so the
private depth-128 bound also preserves the public depth-64 profile. The
validator checks its node/depth budgets independently from byte length.

Scratch is 32 MiB. Fixed descriptor, environment, exact-name hash, mark,
signature, carry and block tables occupy less than 12 MiB. The largest case
hash occupies 4 MiB. All 32 target-edge vectors together need at most 8 MiB;
the unchanged fresh-name quota bounds generated parameter vectors, and
padding/instruction records occupy less than another 4 MiB. Hashes only locate
table candidates: exact source bytes resolve collisions.

Output is 64 MiB. A conservative private bound allows each of 32 arms to
forward 32,768 primitive names, independently of how many names were freshly
generated. Forwarded aliases do not all charge the fresh-name counter. These
lists use less than 20 MiB; generated parameters, decisions, source names and
at most 32*511 inactive-slot drops keep the complete output below 32 MiB.
The 64-MiB output region therefore does not rely on an incorrectly assumed
one-to-one relation between output occurrences and fresh names.

All buffers are private to one call. The image reinitializes the scratch it
uses; an earlier call does not establish initial state. Input bytes are checked
unchanged after native return. Shared code is mapped read/execute only after
copying. This trusted code selection is not an execution sandbox for arbitrary
machine bytes and not a proof of all-input equivalence.

## Output and refusal protocol

The three-buffer HIA entry takes source/readbuf, output/mutbuf and
workspace/mutbuf. A completed semantic result returns `64 + payload_length`.
The eight little-endian u64 header words are:

| Word | Meaning |
| --- | --- |
| 0 | ASCII `HIAMAT01` |
| 1 | Zero, or a declared semantic error ID |
| 2 | Final fresh-name counter |
| 3 | Payload byte length |
| 4–7 | Zero |

Success payloads contain exactly `first` and `blocks`.
`first` contains exactly `ops` and `term`; `blocks` contains the complete
generated Core block objects in the original order. Refusals contain
`{"first":null,"blocks":null}` and retain the precise final counter. The
adapter checks framing, reserved words, extent, counter correlation and object
envelopes. It materializes the declared original error code/message; unknown
statuses or malformed results refuse rather than permitting fallback.

## Validation and evidence scope

`tests/test_hia_enum_match_native.py` verifies checked-in source reproduction
and the unchanged compiler limits, then executes the actual native image.
The retained `_reference_match` algorithm is an independent oracle over real
ordinary elaborator environments, with original reference edge closures and
fresh counters. It compares the full generated CFG, first errors and counters,
including late target failures, duplicate/omitted linear values, permuted
cases, scalar aliases, all 32 variants and exhaustion during name generation.

Ordinary comparisons cover all four composite versions and require byte-exact
normalized Core with the reference match method disabled on the selected run.
Independent VM runs check results, allocation refusal and owner/loan balance.
Actual emitted machine programs use allocator/free wrappers and an invalid-tag
abort control. Private loan-padding descriptors are explicitly synthetic ABI
controls, not accepted source programs. Large repeated zero-width and scalar
target fixtures exercise representation growth without lowering public limits.
Canary, short-buffer, changed-input and concurrent-call controls cover the
native boundary. A real installed-wheel test forbids authoring-module imports
and the reference owner, and requires missing/changed installed source or an
invalid manifest to refuse.

`HEPTA_HIA_ENUM_MATCH_DEVELOPMENT_MANIFEST` is a test-only image reuse option.
It cannot be combined with `HEPTA_HIA_ENUM_MATCH_COLD_REPORT`. A cold report
must bind the complete current source contract and all original qualification
gates before the shared `enum-match` builder publishes a manifest. Development
execution and old compiler reuse do not qualify a changed source tree, replace
whole-language acceptance, activate a deployment or authorize retiring other
production owners.
