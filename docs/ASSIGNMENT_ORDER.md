# Ordinary assignment ownership order

The source checker used to visit an ordinary assignment's destination before
its RHS. Both native emitters and the independent resource lowerer implement
RHS-first assignment. The Rust language reference independently specifies this
order: <https://doc.rust-lang.org/reference/expressions/operator-expr.html#assignment-expressions>.

## Retained baseline

At exact #610 head `b3ed67874af8f6fcc5b9cd7756e6800edf047ed1`, this safe operation
was rejected with `E_USE_AFTER_MOVE`:

```hepta
fn slot(out:mut [usize], data:take Buffer<u8>)->mut [usize] from out effects {alloc,block} {
    release(move data); return mut out;
}
fn main()->Unit effects {alloc,block,panic,write} {
    let owner=buffer(7); let mut values:[usize;1]=[0];
    slot(mut values,move owner)[0]=len(read owner);
    assert(values[0]==7);
}
```

The RHS observes the owner before the target call consumes it. Splitting the
RHS into an immediately preceding local already passed the source/resource
checks and real GCC O0/O3 with UBSan. Conversely, the original checker accepted
`out[index[0] as usize]=dispose(move index)`, even though the RHS consumes the
index owner before the destination reads it. The resource/native gates still
rejected that invalid program; this was not a demonstrated unsafe native
execution or a bypass of those gates.

The three inherited invalid programs' original graphs and generated Rust are
retained as immutable negative controls in `tests/fixtures/assignment_order`.
They remain independently rejected after frontend checking starts rejecting
those sources earlier. The fixture README documents capture provenance; no
failed checker result is made successful to reach a later gate.

## Bounded repair and controls

For non-restoration assignment, obtain the existing pure destination-type
hint, check the RHS exactly once, then check the real destination exactly once.
Keep contextual numeric/array/nominal inference, all mutability/borrow checks,
and the original owned-field restoration preconditions and post-RHS rechecks.
No emitter, resource verifier, raw-store semantics or C subset is changed.

The new suite covers safe and invalid ownership order, returned slice targets,
named effectful indices (still refused by C), nested generic destinations and
implicit constructors, narrow types, stored reference permission/write effects,
and the existing live-owned-field overwrite refusal. Real C/Rust controls
check O0/O3 returned-target ownership, a RHS-mutated destination index, and
flushed RHS/target event traces with exact SIGABRT prefixes. The hosted
Linux x86-64/AArch64 lane requires all 306 selected controls with zero skips,
expected failures or unexpected successes, using pinned Rust 1.90 and GCC.
Local systems without Rust cannot claim that complete native result.

The defect also exists in the simpler checker on current main
`125d11c5454835a7df1dc51915fc49901fbede5b`, where the analogous
`values[position(move owner)]=len(read owner)` rejects incorrectly. This
change is based on #610's existing returned-borrow/resource profiles, not an
unreviewed merge of other draft branches. Full language refinement, global
production qualification, merge and deployment remain outside its scope.
