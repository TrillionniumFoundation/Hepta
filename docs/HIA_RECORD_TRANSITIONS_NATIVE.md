# Native partial-record transitions and borrowing

`HEPTA_HIA_RECORD_TRANSITIONS_MANIFEST` explicitly selects the complete HIA
owner of `record.begin`, `record.take`, `record.insert`, `record.finish`,
`record.abandon` and `record.borrow` in ordinary nominal lowering. Its
operator-owned manifest binds
`examples/hia_bootstrap/record_transitions.hiaasm`, the native image and the
compiler digest. Source programs cannot select this manifest. Selected image,
source, transport and semantic failures never invoke the reference branches.

Together with the separate record-operation owner, these branches cover every
ordinary record operation. Enum construction/tag and match retain their own
native selectors. The enclosing SSA/function/call/task orchestration, type
owner, returned-loan origin processing and final primitive verifier retain
their existing responsibilities. Completing these record branches is not a
claim that all ordinary lowering or the complete system has been rewritten.
Composite versions and their primitive normalization targets are unchanged.
In particular, earlier profiles do not gain partial-record operations merely
because an image is selected.

## Complete native responsibilities

| Operation | HIA responsibility |
| --- | --- |
| `record.begin` | Exact attributes/arity/output kind, empty initialized inventory, complete zero-byte token allocation instructions, counter and binding. |
| `record.take` | Input/field checks, initialized-field lookup and offset, ordered remainder inventory, output comparison, consumption, token creation/reuse, every primitive owner move, and both complete bindings. |
| `record.insert` | Input/field/type checks, duplicate-initialization rejection, declaration-ordered initialized inventory, output comparison, ordered consumption and complete token/field aliases. |
| `record.finish` | Complete initialized-field equality, output comparison, consumption, token drop and complete record binding. |
| `record.abandon` | Empty initialized inventory, empty-output comparison, consumption and token drop. |
| `record.borrow` | Exact field/mode inventory, mode validation before field lookup, primitive owner/view eligibility, output comparison, complete primitive borrow operation and exact loan binding. |

The adapter copies complete native instructions and value bindings. It does
not choose initialized fields, calculate field offsets, decide linearity,
generate fresh names or interpret an instruction-generation plan. Every new
binding keeps the original descriptor and begins with `external=false` and
`consumed=false`. The final primitive verifier still checks actual capability
relationships, including suspension, exclusivity and borrowing during moves.

## Existing type-owner continuations

The surrounding function already resolves source arguments and initially
declared output types before entering a branch. HIA preserves every later
type-owner call at its original point. A query carries data selected by HIA;
the bridge dispatches the existing method and transports its result.

| Operation | Query order after native semantic guards |
| --- | --- |
| `begin` | No further type-owner call. |
| `take` | `partial_record(base, remaining_fields)`, then `parameters(ins["out"])`. |
| `insert` | `partial_record(base, initialized_fields_in_declaration_order)`, then output reparse. |
| `finish`, `abandon` | Output reparse only. |
| `borrow` | `resolve("readbuf" or "mutbuf")`, then output reparse. |

The maximum is three native entries: phase 0, optional phase 1 after type
construction/resolution, and phase 2 after output reparse. Request 1 carries a
base descriptor ID and HIA-generated field names, request 2 carries the loan
primitive, and request 3 requests output reparse. Finish/abandon go directly
from phase 0 to phase 2. The adapter rejects skipped, repeated and reordered
requests. Requests have no instructions, bindings, changed consumption flags
or changed fresh-name counter.

The HIA owner checks the returned partial descriptor against its requested
base, ordered field names and field types before continuing. The type owner
still owns nominal instantiation and its cache/limits. Its exceptions propagate
without semantic fallback. A remainder can enter that cache before a later
output-type refusal, exactly as in the original implementation. Tests restore
the initial cache separately for reference and native runs, compare the full
observable cache contents and analysis counters, and compare method-call order.
They also cover a full type cache and stored-loan refusal before output reparse.

## Exact partial effects

The native result includes effects accumulated before a semantic refusal, and
the caller applies them before raising. Taking a whole record consumes it,
creates its partial token and moves every primitive owner in field order.
A counter refusal between buffer-token names or between nested owner moves
therefore retains the original consumption flags, instruction prefix and final
counter. A field binding is created only after all of its moves succeed.
Taking from a partial record reuses its token and skips token allocation.

Insert consumes the partial record and supplied field in the original order.
Finish/abandon append the token drop at the original point. Borrow leaves the
aggregate live and borrows the original primitive capability. None of those
four operations invents a fresh elaborator name. Native continuation boundaries
do not move type-cache side effects across any of these actions.

The retained six branch bodies are preserved as independent reference owners.
Their `record_field` and `move_field` closures remain unchanged. Differential
tests run both paths against the actual admitted closures; the operation list
is restored in place because the original move helper closes over that exact
list. Reimplementing the reference move helper in a test would not provide the
same independence.

## Private representation and bounds

```text
[phase, serial, operation, attributes, descriptors, values, arguments,
 initial_declared_outputs, resolved_type_id_or_null, reparsed_outputs_or_null]
descriptor = [kind, primitive_flat_types, linear, [[field_name, type_id], ...], base_record_id_or_null]
value = [type_id, primitive_names, external, consumed]
argument = [source_name, value_id]
declared_output = [source_name, type_id]
```

The transport holds every value once and every argument occurrence separately,
preserving alias consumption without duplicating flattened data. It preserves
nominal and partial descriptor identities from the existing interned type
session. HIA compares nominal IDs and primitive names. The bridge does not
hash/compare semantic keys or expand a shared zero-width descriptor graph.
Fields and base descriptors are references, not recursively copied trees.

The HIA image validates exact inventories, safe names, booleans, indices,
primitive names, record-flat correspondence, the partial token/base kind and
phase-specific fields before using them. This is a private representation of
admitted types, not another public type declaration interface.

Public limits remain 8 MiB source, 262,144 JSON value nodes, depth 64, 128
completed/active instantiations, 64 fields, 512 primitive layout slots, 32,768
elaborated value slots and 8,192 fresh names. The private allowances are
256 MiB, 8,388,608 typed nodes and depth 128. Let `N = 262144`, `V = 32768` and
`D <= 2*V + 128*64 + 128 + 1 = 73857`. Actual values and initial outputs share
the first value-slot quota; one output reparse can introduce another `V`
primitive descriptors. Record fields contribute at most 64 primitive
descriptors per interned nominal type, and a loan resolve contributes at most
one more descriptor. New partial types remain within the existing 128-type
budget. The private descriptor table allows 262,144 entries.

| Packet component | Conservative typed-node bound |
| --- | ---: |
| Raw attributes, including keys | `2*N` |
| Held values and primitive names | `5*N + V` |
| Argument occurrences | `3*N` |
| Initial and reparsed outputs | `6*N` |
| Descriptor rows, flats and fields | `7*D + 128*512 + 3*128*64` |
| Root and inventory containers | `32` |
| Total | `4,834,215` |

Charging 24 bytes per typed node uses less than 111 MiB. Four additional
public 8-MiB payload allowances, every held primitive/field name and all
kind/primitive strings still keep the packet below 192 MiB. References prevent
descriptor-depth expansion, and relocated attributes lose their source
ancestors. The native validator checks node count, depth and byte length
independently. These private limits therefore preserve the public profile,
including rejected instructions with large arities.

Scratch is 16 MiB. Fixed tables/state occupy 6,303,744 bytes; all query vectors,
binding records, aliases and up to 512 owner-move records fit within a further
64 KiB. A whole-record take emits at most 514 primitive instructions and uses
at most 515 fresh names within the existing global quota. The 8-MiB result
region exceeds a conservative 3-MiB bound covering `N` consumption flags,
complete operations, aliases and a 64-field query. Every call uses private
buffers, reinitializes used scratch and checks unchanged input after return.
Trusted-image selection is not a sandbox for arbitrary machine bytes or an
all-input equivalence proof.

## Framing and qualification scope

The entry accepts source/readbuf, output/mutbuf and workspace/mutbuf. A normal
return is `64 + payload_length`; the eight little-endian u64 header words are
magic `HIARTN01`, semantic error, final serial, request, payload length and
three reserved zeros. ABI/representation failure returns `0xfffffff1`. The
payload contains exactly `ops`, `consumed`, `values` and `query`. Errors and
requests carry no new binding. A final result has no query. The bridge checks
counter ranges, continuation correlation, binding inventories and strict JSON.

The tests compare exact normalized Core, runtime/resource meaning, original
errors, partial instructions, flags, counters and type-cache/call order. They
include multiple nested owner moves at budget boundaries, 512-slot partial
records, 128-byte field names, wide repeated arguments and the exact value-slot
boundary. Independent HIA VM/native bytes cover requests and refusals. The
combined native type, record, transition, enum and match path disables all five
corresponding hosted reference owners. Real machine allocator failure/free
controls, retained public rejection tests, canaries, depth/short-region checks,
concurrency and installed-wheel custody controls exercise the executable path.

`HEPTA_HIA_RECORD_TRANSITIONS_COLD_REPORT` requests a matching-source cold
fixture. `HEPTA_HIA_RECORD_TRANSITIONS_DEVELOPMENT_MANIFEST` explicitly selects
development evidence; setting both is an error. Default bootstrapped tests
are labelled `BOOTSTRAP_DEVELOPMENT_ONLY`. A predecessor compiler with a pinned
digest remains development evidence even when its bytes match a retained cold
image. Whole-profile source registration, a fresh cold qualification and any
retirement decision remain separate gates.
