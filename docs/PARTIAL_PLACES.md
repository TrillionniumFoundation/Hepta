# Partial owned fields and declared returned-borrow origins

The supported named-place profile now tracks initialization separately for
every struct node and field. An opaque owner (`Buffer`, an owned enum or an
`Owned` type parameter) carries a consumption obligation. A struct's remaining
Copy fields can be read after an owned sibling is moved. Moving the whole
struct makes all of its fields unavailable.

```hepta
struct Pair { left:Buffer<u8>, right:Buffer<u8>, tag:u64 }
fn example()->Unit effects {alloc,block,panic} {
    let mut value=Pair{left:buffer(4),right:buffer(8),tag:7};
    let left=move value.left;
    release(move left);
    assert(value.tag==7);
    value.left=buffer(16);
    drop(move value);
}
```

## Moves, restoration and exits

- A `move` can consume a whole named owner or an arbitrarily nested, statically
  named struct field, subject to the finite 128-level/16,384-place limit.
  It cannot extract through a borrowed input, a returned borrowed view, an
  index or an opaque enum payload. Enum payloads still use consuming `match`.
- Moving a field requires that entire subtree to be initialized. Moving or
  borrowing a parent requires all descendants to be initialized. Sibling
  fields do not overlap, and the independent verifier rejects parent/child
  moves while an overlapping loan remains live.
- Assignment of an owned field restores a **completely moved-out** field of a
  mutable local owner. All enclosing struct nodes must remain initialized.
  It cannot overwrite a live/partially moved field, revive a wholly moved
  parent, assign through borrowed storage or replace a complete owner. The
  right-hand side must transfer an existing owner explicitly or produce a
  fresh owner. Its evaluation is checked before restoration occurs.
- Branches and match arms that continue must agree on every initialization
  token. Loop backedges preserve their incoming tokens, allowing move/use/
  restore cycles. A short-circuited expression cannot consume an owner.
- Every normal, early and error return consumes every remaining opaque owned
  leaf. After explicitly consuming all owned fields, a struct's Copy fields
  need no drop. `drop(move parent)` is rejected if a child is missing; there
  is no implicit destructor for the remainder. Panic remains abort in the
  current native profile and does not imply process-resource rollback.

Generic bodies use the same rules before instantiation. For example,
`fn extract<T:Owned>(item:take Box<T>)->T` can return `move item.value` while
leaving a Copy metadata field behind. Arrays of owners, user-defined `Drop`
implementations, stored references and self-referential values remain outside
the supported profile.

## One declared origin among several inputs

```hepta
fn selected(a:read [u8], b:read [u8])->read [u8] from a effects {} {
    return read a;
}
```

`from a` selects one borrowed parameter as the result lifetime's source. The
other inputs do not extend or shorten that lifetime. Mutable returned views
require a mutable selected input. Each return, including a chain of returned
views, must originate at that declared input. Returning another input, a
local or an owned argument is rejected. A function with exactly one borrowed
input can continue to omit `from`. A value return cannot declare an origin.

The Rust backend emits an explicit named lifetime only where an origin is
declared. HSIR, CFG signatures and public interface hashes include the origin,
so changing it invalidates an earlier interface-bound Agent edit. `from` is a
contextual keyword; existing identifiers with that name remain valid.

This is a single-origin relationship, not general lifetime polymorphism. A
function that conditionally returns either of two unrelated inputs, stored
reference fields and arbitrary outlives constraints are still rejected.

## Independent resource IR v3

`hepta.resource-ir.v3` represents the same finite place-state protocol through:

| Operation | Meaning |
| --- | --- |
| `take_field {place, dest}` | Transfer a complete owned field subtree into a distinct typed owner slot. |
| `init_field {place, src}` | Consume a distinct typed owner to restore an empty field of a mutable local struct. |
| `forget {src}` | End local aggregate storage only after every owned payload is consumed and no loan remains. This emits no native action. |

The verifier derives struct shapes from its own closed type table. Its state
records initialized nodes, live loans and enum facts; all joining edges must
agree. Source lowering retains explicit operations for nested partial moves,
restoration and lexical scope exit. V3 return signatures can name one origin
among multiple borrowed parameters. Legacy v1/v2 graphs remain accepted with
their previous feature limits and cannot opt into these operations.

The graph verifies its stated ownership/loan transitions. Scalar values are
abstract, native code is still generated from checked syntax, and neither
source-to-IR refinement nor whole-language type soundness is claimed. The
sequential resource graph does not model task runtime behavior.

## Qualification and actual failures

Run with the pinned Rust compiler available:

```sh
python -m unittest tests.test_partial_places
python -m tools.qualify_places --output artifacts/places-qualification.json
```

The qualifier retains the exact v3 graph, source/compiler identities, native
build identities and raw process output. A fresh independent verifier process
checks the serialized sequential graph. The native allocator harness observes
real allocations of the three deliberately chosen Buffer sizes; it does not
count runtime infrastructure as whole-process allocation accounting.

The sequential cases execute normal return, early return, one real allocator
refusal, recovery and five move/restore loop iterations. They expect 16
successful Buffer allocations and 16 frees with zero remaining tracked bytes.
The separate concurrent project executes eight cooperative cancellations and
eight explicit worker failures after partial moves, joins every worker, and
expects another 32 allocations/frees with zero remaining tracked bytes.
These expected counts are checked against actual native output; they are not
promised results for an unexecuted qualification.

Six graph mutations must be rejected. Unit regressions additionally cover
overlapping/disjoint loans, forged types, duplicate field extraction,
overwriting a live sibling, missing restoration, wrong origins, legacy
profiles, branch/loop mismatches and 29 malformed qualification reports.
`validate_places_qualification` independently replays current source lowering,
checks the retained graph and requires all native observations and identities.
It does not turn historical output into a new execution.
