# HIA v6 P1: successful integer casts preserve safe finite heap bounds

**Scope:** One arithmetic/interval transfer in the existing
`hepta.hia_heap_bound.analyze_constant_live_heap`. No second verifier,
parser, compiler, Resource IR or native backend.

**Exact development parent:** PR #249 commit
`f42c84869116d2db59750c9d214ed11b2abfaf51`. Keep this stacked,
not directly merged into `main`.

## Proven postconditions of the existing HIA VM and LLVM operations

1. `int.cast(mode=checked)`: a value outside the destination's full
   signed/unsigned machine domain **traps before the next instruction**.
   Therefore the only continuing results lie in the intersection
   `[source.lo,source.hi] ∩ [destination.min,destination.max]`.
   This is a bound on the *successful continuation*, not a promise that an
   unknown negative value passes the cast.
2. `int.cast(mode=wrap)`: an exact source is evaluated modulo the machine
   width, respecting destination signedness. If an interval may wrap, the
   only automatic result used here is the **entire destination domain**
   for six small integer types. It must never be treated as an identity cast
   or an unchanged source interval.
3. `i8/i16/i32` formal parameters can have any representable value,
   including all negatives. The verifier already checks these parameter
   types. Their complete signed intervals now seed the established analyzer;
   no caller inputs are presumed nonnegative.
4. `u8/u16/u32` formal parameter handling remains unchanged except for
   sharing the exact existing `integer_range` helper. Full-domain
   `i64/isize/u64/usize` parameters **remain unknown** without an explicit
   narrowing operation in this bounded-profile analyzer.
5. Regardless of source operand precision, *successful* small-destination
   checked or wrapping casts have a target-domain bound. A subsequent
   successful checked cast to `usize` intersects it with the nonnegative
   domain, permitting a finite upper bound only if the next allocator
   extent is also within `MAX_REQUEST`.

## Concrete example

The HIA instruction sequence `i8 argument → checked usize →
buffer.new → owner.drop` has verified successful-path peak <=127 bytes.
Negative inputs trap *before* allocation. This result does **not** imply
that every call succeeds, or that all negative inputs can be reinterpreted
as a small positive size.

Another example, `usize input → wrap u8 → checked usize → buffer.new`,
has peak <=255 payload bytes for **every** valid caller input, even
`2^64-1`. `usize → checked u8` instead traps on inputs >255.
Unknown direct `usize → buffer.try_new` continues to reject a small
bounded policy.

## Independent executed mathematical control

A separately executed Python 3.13 pure-transfer control exhaustively
checked 263,168 8/16-bit input/mode combinations across eight conversion
profiles, including every signed `i16` input, checked trapping, modular
signed wrapping and unsigned narrowing. All observed continuing outcomes
belonged to the predicted intervals. This is NOT the actual integrated
Hepta Core/VM/LLVM full-checkout run; exact-head repository tests must
be executed before claiming complete native qualification.

New in-repository tests exercise actual `verify_program`,
`execute_program` and `analyze_static_budget` with signed positive and
negative samples, checked out-of-range traps, full-width wrapping,
max-1 rejection and continuing unknown-width refusal.

```sh
python -m unittest tests.test_hia_heap_cast_domains \
  tests.test_hia_heap_scalar_exact tests.test_hia_heap_intervals \
  tests.test_hia_heap_bound -v
```

## Remaining production blockers

This proves no whole-language source→Core→LLVM refinement, general
provenance, arbitrary C/C++ conversion, global allocator overhead/RSS
bound, real-model Agent economics, physical DMA/GPU, or production p99.
The output is a conservative requested-live-payload bound, not a runtime
allocator or hardware theorem.

`whole_project_blockers_closed=false`
