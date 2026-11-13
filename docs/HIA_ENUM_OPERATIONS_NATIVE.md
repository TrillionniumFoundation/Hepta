# Native enum construction and tag lowering

`HEPTA_HIA_ENUM_OPERATIONS_MANIFEST` explicitly selects the HIA implementation
of the complete `enum.make` and `enum.tag` branches in the ordinary nominal
elaborator. The operator-owned manifest binds
`examples/hia_bootstrap/enum_operations.hiaasm`, its image and compiler digest.
Submitted source cannot select a manifest. A selected image, source, transport
or semantic refusal never enters the retained reference branch.

HIA owns exact attribute admission, declared enum-output checks, variant names
and selection, payload type comparison, ordered linear consumption, fresh-name
allocation, inactive variant padding and complete emitted Core instructions.
It emits zero/false/unit padding, zero-byte `buffer.try_new` owners and empty
chains; inactive loan invention preserves the original refusal. It owns tag
input checks, output arity/type equality and the final alias binding. The
adapter copies complete instruction objects, consumption flags, bindings and
the fresh-name counter. It does not interpret an instruction-generation plan.

The unchanged reference branch is retained as an independent differential
oracle and as the unselected route. Selection is explicit, not a claim that
the entire elaborator has moved to HIA. Source/function orchestration, the
preceding argument/name checks, the type owner, record operations, tasks,
ordinary calls, primitive operations and the final primitive verifier retain
their existing boundaries. Enum match has a separate native selector. Public
composite v1 still lowers to primitive v6, v2/v3 to v7 and v4 to v8.

## Exact type-owner ordering

The enclosing function resolves instruction arguments and declared outputs
before reaching either enum branch. This work remains before native entry.
`enum.make` requires no additional type-owner calls. `enum.tag` originally
resolves primitive `u32`, reparses its output declaration, checks output types,
and only after success resolves the type used in the resulting binding.

The HIA owner preserves this sequence with bounded continuations:

| Phase | HIA decision and permitted following action |
| --- | --- |
| 0 | Check empty attributes and one enum argument. On success request 1. |
| 1 | Receive `resolve("u32")` and the reparsed output declaration; perform exact output equality. On success request 2. |
| 2 | Receive the final `resolve("u32")` result; bind that exact descriptor to the original primitive tag name. |

Only the HIA request triggers each call to the existing type owner. The bridge
does not compare types or decide whether output checking succeeded. A type
owner's exception propagates at the original point. Refusal before a request
does not call that owner, and mismatched output types never trigger the final
resolve. The adapter rejects skipped, repeated or effect-producing requests.
Tag operations never change the fresh-name counter or consume their argument.

## Partial effects and independent identity

An enum construction can fail after consuming a prefix of its arguments or
emitting a prefix of its padding. Reusing one linear source twice consumes the
first occurrence before rejecting the second. A buffer padding slot creates
its size constant, owner name and success name in that order; a fresh-name
failure can occur between those steps. Native results include these partial
effects, and the caller applies them before raising the original error.

The private packet holds each original value object once and stores every
argument occurrence separately. Repeated aliases therefore share the same
consumption flag without duplicating their flattened data. The packet also
holds existing nominal descriptors by identity. Both retained type owners
intern nominal descriptors within one elaboration. HIA compares nominal IDs,
and compares separately materialized primitive descriptors by primitive name.
No Python semantic equality, nominal display-key expansion or object address
is used to decide equality in the selected path. HIA-issued types and hosted
types follow the same packet representation.

```text
[phase, serial, operation, attributes, descriptors, values, arguments,
 declared_outputs, expected_tag_type, reparsed_tag_outputs, bound_tag_type]
descriptor = [kind, primitive_flat_types, linear, [[variant, field_type_ids], ...]]
value = [type_id, primitive_names, external, consumed]
argument = [source_name, value_id]
declared_output = [source_name, type_id]
```

This is an internal representation of admitted types, not another public type
declaration format. The HIA image validates exact packet inventories, types,
indices, enum-flat correspondence, safe names, boolean flags, phase fields
and buffer sizes before semantic work. It validates private typed node and
depth budgets independently from byte length.

## Private capacity preserves public limits

Public source remains bounded by 8 MiB, 262,144 JSON value nodes and depth 64.
Nominal elaboration still allows 128 completed/active instantiations, 512
primitive slots per nominal layout, 32 variants, 64 fields per variant, 32,768
elaborated value slots and 8,192 fresh names. These limits are unchanged.

The private packet allows 256 MiB, 8,388,608 typed nodes and depth 128. Let
`N = 262144` and `V = 32768`. A conservative bound on held descriptors is
`D <= 2*V + 128*511 + 128 + 2 = 131074`. Actual values and the first declared
output inventory share the original value-slot quota; reparsing tag outputs
can materialize at most another `V` primitive descriptors. Nominal descriptors
are interned, including zero-width types. Primitive enum-field descriptors
contribute at most 511 per enum. Two additional descriptors cover tag resolves.
The private table permits 262,144 descriptors, so this does not narrow source.

| Packet component | Conservative typed-node bound |
| --- | ---: |
| Raw attributes, including object keys | `2*N` |
| Held values and their primitive names | `5*N + V` |
| Argument occurrences | `3*N` |
| Initial and reparsed declared outputs | `6*N` |
| Descriptor graph, flats, variants and fields | `6*D + 128*512 + 128*32*3 + 128*32*64` |
| Root and inventory containers | `32` |
| Total | `5,353,516` |

Charging 24 bytes per typed node uses less than 123 MiB. Even additionally
charging four complete public 8-MiB payloads for attributes, argument names
and repeated declarations, 128 bytes per held primitive name, every variant
name and all primitive/kind strings keeps the private packet below 192 MiB.
The 256-MiB buffer therefore has room beyond this conservative bound. The
descriptor graph uses IDs instead of recursive descriptor expansion. Its
container depth is bounded independently, and relocated attributes lose
their source ancestors; the private depth-128 validator preserves depth-64
public inputs.

Scratch is 16 MiB. Fixed descriptor/value/consumption tables and operation
state occupy 6,303,744 bytes. Dynamic vectors and records for at most 512
result slots and 1,023 emitted instructions fit within a further 160 KiB.
The output region is 8 MiB: at most `N` boolean flags use under 1.6 MiB;
complete padding operations, a single binding and all original/generated
names keep the complete result below 3 MiB. These bounds count malformed
public arities that reach branch admission, including many repeated
zero-width arguments and declared outputs.

Each call uses private buffers. The image initializes used state, checks
extents, guards allocation/output growth and never writes input bytes. The
adapter checks unchanged input after return. The selected image is trusted
native code mapped executable after copying; these bounds are not a sandbox
for arbitrary machine bytes or a proof of all-input semantic equivalence.

## Result frame and validation

The entry receives source/readbuf, output/mutbuf and workspace/mutbuf. Its
normal result is `64 + payload_length`. The eight little-endian u64 header
words are magic `HIAEOP01`, semantic error, final serial, continuation request,
payload length and three reserved zeros. ABI/representation failure returns
`0xfffffff1`. The payload contains exactly `ops`, `consumed` and `values`.
Errors and continuation requests carry no value binding. Final success
carries exactly one binding. Continuations carry no operations or changed
consumption flags. Counter bounds and continuation phases are checked by
the adapter; source and image digests are checked by the installed loader.

`tests/test_hia_enum_operations_native.py` covers generated-source equality
and unchanged compiler limits, exact Core for all four composite versions,
original error/partial-state/type-owner-call differentials, duplicated owners,
inactive loans, buffer padding at fresh-name boundaries, wide repeated inputs,
maximum-width/variant/name layouts and the exact value-slot boundary,
independent HIA VM versus actual image bytes for all tag phases, composed
native type/match owners, real machine allocator/free behavior, private-buffer
canaries/depth/short-region controls, concurrent calls and installed-wheel
execution with authoring imports and the reference branch disabled. Installed
source mutation, deletion and invalid manifest controls must fail closed.

The test class accepts a matching cold report via
`HEPTA_HIA_ENUM_OPERATIONS_COLD_REPORT`. An explicit development image uses
`HEPTA_HIA_ENUM_OPERATIONS_DEVELOPMENT_MANIFEST`; setting both is an error.
The default fixture bootstraps a development compiler and is labelled
`BOOTSTRAP_DEVELOPMENT_ONLY`. Reusing a pinned predecessor image during
development does not constitute a current-source cold qualification. Source
registration, whole-profile qualification and any retirement decision remain
separate gates.
