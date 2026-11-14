# Native record construction, unpack and projection

`HEPTA_HIA_RECORD_OPERATIONS_MANIFEST` explicitly selects the HIA owner of the
complete `record.make`, `record.unpack` and `record.get` branches in ordinary
nominal lowering. The operator-owned manifest binds
`examples/hia_bootstrap/record_operations.hiaasm`, its image and compiler digest.
Program bytes cannot select the manifest. A selected source/image/transport
or semantic refusal never invokes the retained reference branch.

These three operations originally emit structural aliases rather than new
primitive instructions. The HIA owner therefore returns their complete value
bindings and consumption state, with an empty instruction sequence and the
unchanged fresh-name counter. The bridge copies that result; it does not
compute field offsets, compare types, flatten arguments, derive external-loan
flags or implement an alias-generation plan.

| Operation | Complete native responsibility |
| --- | --- |
| `record.make` | Exact attributes and nominal output kind, ordered field-type equality, ordered linear consumption, complete flattened aliases, and the original external flag. |
| `record.unpack` | Exact attributes and input kind, output type/arity equality after the original reparse, consumption of the record, ordered field slices, exact field descriptors and inherited external flags. |
| `record.get` | Exact attributes and input kind, field-name validation and lookup, partial-record token offset, uninitialized versus unknown field errors, prohibition against copying linear fields, output equality and the complete field alias. |

The preceding source/name/argument admission, nominal type owner, function
orchestration, return-origin handling and final primitive verifier retain their
existing boundaries. Other record operations, including `record.borrow` and
partial-record transitions, are separate responsibilities. Reading an
initialized scalar field of a partial record is included in `record.get`;
creating or changing that partial record is not moved by this owner. Enum and
match owners have separate selectors. This does not claim a native rewrite of
the whole elaborator or the rest of the system. Composite v1 still produces
primitive v6, v2/v3 produce v7, and v4 produces v8.

## Observable state and error order

`record.make` checks every field's type before consuming any argument. It then
consumes arguments in source order. Reusing a linear value consumes the first
occurrence and rejects the second, preserving that partial state without
creating an output binding. The native caller applies the returned consumption
flags before raising the original error.

The construction's external flag remains exactly
`all(argument.external or not argument.type.linear) and not output.type.owns`.
An empty record consequently has `external=true`. A record carrying a local
loan does not become external merely because it owns no buffer. Unpacking
propagates the input record's external flag to every field. Projection always
creates the original non-external binding and refuses every linear field,
including externally supplied loan fields.

The original unpack and get branches reparse output declarations after their
semantic guards. HIA preserves that point with one continuation. Phase 0
checks attributes, operands and, for projection, field/loan policy. Only a
successful native request triggers the existing type owner's
`parameters(ins["out"])`. Phase 1 receives those descriptors, performs type and
arity comparison in HIA, then consumes/binds. A type-owner exception propagates
at its original point. Failed field lookup or linear projection never triggers
the reparse. The adapter rejects skipped/repeated continuations, changed
consumption during a request, nonempty primitive operations and any changed
fresh-name counter.

Bindings retain the exact descriptor used by the original branch: construction
uses the initially declared record, while unpack/get use the record's field
descriptor. The reparsed primitive descriptor is used for equality, not silently
substituted for the bound field descriptor. Differential tests compare these
object identities, complete aliases, external/consumed flags and type-owner
call traces.

## Private representation and descriptor custody

```text
[phase, serial, operation, attributes, descriptors, values, arguments,
 initial_declared_outputs, reparsed_outputs]
descriptor = [kind, primitive_flat_types, linear, [[field_name, type_id], ...], base_record_id_or_null]
value = [type_id, primitive_names, external, consumed]
argument = [source_name, value_id]
declared_output = [source_name, type_id]
```

The bridge holds each input value object once and retains every argument
occurrence separately. Aliases share one consumption flag without repeatedly
copying their flattened names. It also holds nominal descriptors by object
identity. Both existing type owners intern nominal and partial descriptors
within one elaboration. HIA compares nominal IDs directly and primitive
descriptors by primitive name. Neither Python type equality nor an expanded
nominal display key decides equality on the selected path.

Record fields and partial-record base descriptors use IDs, so a shared
zero-width type graph does not recursively expand. Enum/task fields need only
their existing kind, flat layout and linear flag. This private graph represents
already admitted types and is not a public alternative type declaration format.
The HIA image validates exact inventories, indices, safe names, booleans,
primitive names, record-flat correspondence and the partial-record buffer
token/base kind before semantic access.

## Capacity without a smaller public language

The public limits remain 8 MiB of source, 262,144 JSON value nodes, depth 64,
128 completed/active nominal instantiations, 512 primitive layout slots,
64 record fields, 32,768 elaborated value slots and 8,192 fresh names.
These operations remain legal at serial 8,192 when they need no fresh names.

The private typed tree permits 256 MiB, 8,388,608 nodes and depth 128. Let
`N = 262144` and `V = 32768`. Held descriptors are bounded by
`D <= 2*V + 128*64 + 128 = 73856`: actual values and initially declared outputs
share the value-slot quota; the one output reparse can materialize another
`V` primitive descriptors; each interned record contributes at most 64
primitive field descriptors. Zero-width nominal descriptors remain interned.
The descriptor/value tables each allow 262,144 entries.

| Packet component | Conservative typed-node bound |
| --- | ---: |
| Raw attributes, including object keys | `2*N` |
| Held values and primitive names | `5*N + V` |
| Argument occurrences | `3*N` |
| Initial and reparsed output inventories | `6*N` |
| Descriptor rows, flats and fields | `7*D + 128*512 + 3*128*64` |
| Root and inventory containers | `32` |
| Total | `4,834,208` |

Charging 24 bytes per node uses less than 111 MiB. Four complete public
8-MiB payload allowances cover attributes, argument names and repeated output
declarations. An additional 128 bytes per held primitive name, every field
name and all kind/primitive strings still keeps the packet below 192 MiB.
The 256-MiB limit therefore has room beyond the conservative bound. Descriptor
references prevent recursive expansion; relocated source attributes lose
their function/block ancestors. Private depth 128 preserves public depth 64.
The native validator checks byte length, node count and depth separately.

Scratch is 16 MiB. Fixed tables/state occupy 6,303,744 bytes, and all dynamic
binding records and alias vectors fit in a further 16 KiB: at most 64 bindings
and 512 copied primitive names. Output is 8 MiB. Even `N` consumption flags,
64 long output names and 512 long primitive names fit below 2 MiB. These bounds
include bad public arities that reach branch checks; they do not assume only
successful source instructions arrive.

Each invocation owns its source/output/workspace buffers. The image initializes
used scratch and checks bounds; the bridge verifies unchanged source after
return. Trusted selected code is copied before executable mapping. This is
not a sandbox for arbitrary machine bytes or a proof of all-input equivalence.

## Protocol and evidence controls

The entry takes source/readbuf, output/mutbuf and workspace/mutbuf. A completed
result returns `64 + payload_length`. Its eight little-endian u64 header words
are magic `HIAREC01`, semantic error, unchanged serial, continuation request,
payload length and three reserved zeros. Representation/ABI failure returns
`0xfffffff1`. The JSON result contains exactly `ops`, `consumed` and `values`.
Errors and requests have no bindings. Successful construction/projection has
one binding; successful unpack has zero through 64. All bindings are complete
and initially unconsumed; `ops` is always empty.

`tests/test_hia_record_operations_native.py` covers exact checked-source
generation and unchanged compiler limits, all four composite schemas, original
branch/state/type-call differentials, every public branch error, duplicate
linear arguments, nominal identity, empty/nested aliases and external loans.
It checks initialized/uninitialized partial fields, returned-loan origin
preservation, partial tasks, maximum-width records and exact value-slot limits.
Independent HIA VM and actual image bytes are compared across continuation
phases. Combined native type, record, enum and match owners run with their
reference implementations disabled. Actual machine allocator/refusal/free
controls, short buffers, canaries, excessive depth and concurrency exercise
the executable boundary. A real installed wheel runs with authoring imports
and reference record operations disabled, and rejects missing/modified source
or invalid manifests.

`HEPTA_HIA_RECORD_OPERATIONS_COLD_REPORT` requests a matching-source cold
fixture. `HEPTA_HIA_RECORD_OPERATIONS_DEVELOPMENT_MANIFEST` explicitly selects
development evidence; supplying both is an error. Default bootstrapped fixtures
are labelled `BOOTSTRAP_DEVELOPMENT_ONLY`. A pinned predecessor compiler used
for development does not qualify the current whole source tree. Shared source
contract/workflow integration, current-source cold qualification and retirement
of remaining owners are separate gates.
