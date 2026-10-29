# Finite source unit enums through canonical Core

The standalone source adapter accepts concrete enums with 1–32 unit variants.
A unit variant has no payload. The existing source checker still resolves
nominal types, checks constructors and requires exhaustive matching. The
adapter emits ordinary primitive v1 or v8 Core; no instruction, wire schema,
runtime or ownership rule is added.

```hepta
enum BuildError { Empty, AboveLimit, AllocationFailed }

fn error_score(error: BuildError) -> u64 effects {} {
    match error {
        BuildError::Empty => { return 101; },
        BuildError::AboveLimit => { return 202; },
        BuildError::AllocationFailed => { return 303; },
    }
}
```

These Copy values can pass through existing internal value/read/mut calls,
record fields, assignments and loop/branch joins. Existing closed generic
functions or records may instantiate with a concrete unit enum; this does not
admit a generic enum declaration. Every enum declaration, including unused
ones, must satisfy the finite unit profile. Payload enums, generic enums and
recursive enum layouts remain outside this source route.

## Representation and control flow

Each variant uses its declaration-order index in a `u32` slot. Fresh source
checking retains nominal distinctions before scalarization: unrelated enums
are not interchangeable with each other or with integers, and source casts
cannot manufacture a tag. This is the same tag type and finite variant limit
used by the existing composite normalizer.

A source `match` evaluates its scrutinee once. The adapter carries its value
and all live capabilities through explicit Core blocks, compares each tag,
and merges only continuing arms with the existing exact resource-state rules.
The final variant also has an explicit comparison. A malformed primitive
caller supplying an out-of-range tag reaches the existing `user` trap instead
of selecting the final source arm. The trap is a conservative Core effect;
valid closed source constructs only declared tags.

Mutable scalarized arguments use the existing call return/writeback mechanism.
An enum field occupies one scalar slot; it does not become an owner or a loan.
Overlapping mutable/read source arguments remain subject to the existing
source-access check. Local borrowed-view declarations and their scalar-label
restriction are unchanged: an enum is not silently admitted as a stored-view
label, nor are returned loans allowed to escape into stored values.

## Result and cleanup

`Result<Packet, BuildError>` reuses the existing Result representation: one
Boolean discriminator plus both payload layouts. An inactive enum slot holds
its first variant's tag. An inactive buffer slot remains a real empty Core
owner and is explicitly consumed on the selected Result arm. No new heap
allocation implements the enum tag, and no destructor is invented.

The fixture `examples/hia_program/source_unit_enums.hepta` combines a three
variant error with an owned `Packet`, a Copy enum field, scalarized mutable
calls, a generic identity call, loops, one-variant matching and a match
scrutinee with an observable counter update.

For `packet_case(5, 19, 0)`, normal execution returns `81`: two allocations,
two frees, peak requested payload eight bytes and no remaining owner or loan.
Refusing the second allocation returns `303` through
`BuildError::AllocationFailed`: one allocation/free, peak payload three bytes,
and the guard plus inactive empty owners all consumed. The native allocator
observer injects an actual `NULL` return at that allocation. VM budget stops
retain the actual stopped resource ledger; they do not run cleanup after the
stop. These payload counts are not RSS measurements.

## Public boundary

Original source signatures determine public scalar entries before generic
specialization or scalarization. An enum parameter or result, a record
containing one, a borrowed parameter, or a generated generic instance does
not become public because its internal representation contains a `u32`.
Explicit enum C ABI declarations remain rejected.

Tests exercise the public source route, canonical serialization/reverification,
the VM entry gate and bound Rust execution. Actual LLVM shared-library symbol
inspection, failed symbol lookup and a failed C link demonstrate that private
enum helpers are absent from the public native boundary. An explicit primitive
adversary separately calls a private helper with invalid tags and observes
the specified VM/Rust trap and native abort; that mutated Core is not a newly
accepted source enum ABI.

## Reproduction and limits

```sh
python -m unittest -v tests.test_hia_source_unit_enums
python -m unittest -v tests.test_hia_program_source tests.test_hia_source_exports \
  tests.test_hia_source_partial tests.test_hia_source_local_views \
  tests.test_hia_returned_loans tests.test_hia_routes
```

The increment compares independently specified finite values with Python Core,
the actual Rust Machine, source-to-Rust native code and direct Core-to-LLVM
native code. It checks complete Rust/Python resource reports, every step stop
of the owned success case, allocation refusal and the actual native export
boundary. Native or Rust tests skipped for missing tools do not qualify.

This source increment does not establish arbitrary recursive ADTs, general
memory/provenance, complete partial initialization, escaped or external
lifetimes, asynchronous cancellation, a general enum C ABI, source/backend
refinement or whole-language soundness. Python remains the production Core
admission authority.
