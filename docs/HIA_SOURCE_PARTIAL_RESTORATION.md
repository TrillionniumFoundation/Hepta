# Source owned-field restoration through executable HIA

The checked source frontend now lowers assignment to a fully moved-out named
owned field. The existing source checker already tracks initialized places;
the independent Resource IR represents `take_field` and `init_field`. The
standalone HIA adapter now carries the same legal source path into ordinary
primitive Core operations instead of refusing every resource-valued assignment.

```hepta
struct Pair { left: Buffer<u8>, right: Buffer<u8>, tag: u64 }
export "C" fn restore() -> usize effects {alloc,block,panic} {
    let mut p = Pair {left: buffer(3), right: buffer(5), tag: 7};
    release(move p.left);
    p.left = buffer(9);
    let total = len(p.left) + len(p.right);
    drop(move p);
    return total;
}
```

The fixture returns `14`, with three allocator-visible allocations and frees,
peak requested payload `14` bytes, and no owner or loan left at normal return.
The adapter emits explicit primitive `owner.move`, allocation and `owner.drop`
operations. Core verification independently checks those resource transitions;
the VM and LLVM backend do not parse the original source.

## Admission and state boundaries

Every lowering starts with fresh source checking. An assignment may restore
only a mutable named owned field whose entire source subtree was moved out and
whose enclosing records are still initialized. The adapter additionally checks
that all destination resource slots are absent owners, the source/destination
layouts agree, and the replacement does not carry a borrowed capability.
An assignment never overwrites a live owner or revives a moved parent.

Copy fields use immutable scalar SSA values. Taking a linear record does not
invalidate an earlier scalar copy; restoring that record replaces only the
destination's scalar values and owned slots. Resource SSA identities continue
to be consumed across every alias. Exact initialized-slot and resource-alias
states must agree at branch joins and loop backedges.

`examples/hia_program/source_partial_restore.hepta` contains ordinary,
fallible, branching, early cancellation, looping and nested generic cases.
After the old left field is released, failure of `try_buffer(9)` at allocation
attempt three returns error code `1`. The inactive empty result owner and the
remaining right owner are consumed: two allocations, two frees, peak requested
payload `8`, no live bytes or owners. The native observer independently injects
that same allocation failure and checks its actual allocator counters.

An infallible `buffer(9)` failure instead traps. A trap or VM budget stop retains
the actually stopped ledger; it does not promise source unwinding or cleanup of
the remaining right owner. Tests observe the retained five payload bytes and
one owner on that trap, and check every step prefix of the normal example.

## Analysis and version scope

This source subset still lowers to primitive v1. The existing static event and
constant live-payload analyzers reverify the emitted Core and qualify the four
acyclic restoration functions at a `14` byte requested-payload limit. The loop
has a finite synchronous frame bound but is refused by the acyclic tick
analyzer; this change does not infer termination from a source `for` loop.

Composite partial-record v3 is a separate input grammar, normalizing to
primitive v7. Its explicit initialization-state tokens are described in
`HIA_PARTIAL_RECORDS_V3.md`. Source records continue to use the existing finite
scalarization and fresh source-place checks. This change does not introduce a
new primitive memory model, arbitrary layout, raw pointer provenance or general
recursive source ADTs. It does not add stored loans to partial nominal states,
or turn v3 into the primitive v8 parameter-bound returned-loan grammar.

All payload counts exclude allocator overhead and process RSS. The tests and
native observations provide finite evidence, not a source-to-Core refinement
proof or whole-language safety theorem.

## Focused verification

```sh
python -m unittest -v tests.test_hia_source_partial
python -m unittest -v tests.test_hia_partial_record tests.test_hia_partial_record_scenarios
```

The first module checks the real source checker, independent Resource IR,
canonical executable Core, static analyses, VM, and direct LLVM. Its negative
cases include live overwrite, moved-parent revival, duplicate field movement,
incompatible branches, unbalanced loop initialization, immutable restoration,
missing cleanup, and a forged primitive loan retained across field movement.
Native methods require an actual selected Clang; a skipped native method is not
native qualification.
