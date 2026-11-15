# R12: ordered eight-byte comparisons

## Status and exact scope

This is a private, authored successor to the actual R11 source. It has not
been generated, verified by the product Core checker, compiled, packed, or
executed. The existing R11 source, original 107 function interfaces and block
edges, original tests and all prior failed observations remain unchanged.

The new generator adds one exact Core projection after R11's three existing
projections. Only `f14/b0`, `f106/b5` and `f106/b18` change. Two private
single-block helpers are appended as `f107` and `f108`; their second four-byte
offsets are the original constants 0 and 120. The candidate has 109 functions,
1458 blocks and 6308 operations before native lowering. The original limits
of 128 functions, 1536 blocks and 8192 operations remain. All 105 other
original functions, including the full `f25` and `f24`, are unchanged.

`draft/file_render_checker_word64_eqbytes.hepta` is a deterministic text
projection for inspection, not an actual generated asset. Future generation
must independently render and verify the complete document, prove the full
inverse to the actual 396167-byte R11 input, and bind its actual output.

## Actual read and error order

At each of the three sites, the first original call instruction stays at the
same position, with the same evaluated view and first offset. No constant or
other instruction is moved ahead of that call. Each new helper performs all
eight real `buffer.load:u8` operations in this order:

1. `w[a]`, `w[(a+1) mod 2**64]`, `w[(a+2) mod 2**64]`, `w[(a+3) mod 2**64]`;
2. `w[b]`, `w[b+1]`, `w[b+2]`, `w[b+3]`, where the original `b` is 0 or 120.

Every load retains the original `_underlying` and bounds checks. There is no
whole-range preflight, early comparison return, skipping of equal/overlapping
reads, or load widened to a machine word. All eight loads finish before the
four byte comparisons. Address additions use `int.add.wrap`. No address
increment is added after either group's final load or after the eighth load.
Dirty bytes, arbitrary valid 64-bit offsets, short storage, expired/cyclic
views, aliases and the original first byte failure do not need a new
initialization or field-range invariant. The helpers never write storage.

## Why the old scalar pack cannot add a language trap

The original `f25` casts each actual `u8` load to 64-bit `usize` using wrap,
then forms the little-endian number with three shifts by 8 and three ORs.
Its intermediate maxima are 65280, 65535, 16776960, 16777215, 4294967040 and
4294967295. Shift counts are within 0..63; all casts and resulting scalars
are valid. Thus after its four loads the old body has no arithmetic, bounds,
ownership, allocation or scalar-validation trap. Base-256 uniqueness proves
that equality of the two packed words is exactly the conjunction of the
four byte equalities. For `adjacent`, a final pure `bool.not` retains `!=`.

The old packing instructions can still consume the last available fuel or
be interrupted by the host. This successor intentionally changes fuel use;
it does not claim identical budget-stop positions, timings or arbitrary
asynchronous host interruptions. Every actual gate retains the old limits.
An old budget failure stays a historical failure.

## Calls, resources and observable diagnostics

The first call has the same operands and original instruction position. Both
old `f25` calls are sequential at caller depth + 1. The replacement helper is
also at caller depth + 1 and contains no calls. The original `_Machine`
checks depth before its entry tick. If the original first call would fail
the depth cap, so does the new first call at the same point. If the first old
call returned, the second sequential call could not newly exceed the same
fixed cap. No extra frame is introduced.

`mutbuf` is a borrowed argument, not an `OWNERS` type. Neither the old `f25`
nor the new helper allocates, borrows, ends, drops or returns a view. Resource
counters and view/owner state are consequently unchanged by this replacement.

The fixed interpreter's public report contains the entry function, source
identities, steps, resources and error code/message. It has no private call
stack field. On the same first failing byte access, the standard exception
class, code and message remain identical. The interpreter's call nesting at
that access remains one callee frame. Private function identifiers, call
histograms, the number of sequential invocations, Python traceback locals,
source hashes, scalar instruction counts and fuel-stop locations do change.
No exact private-trace or Python traceback-provenance identity is claimed.

The retained original `f25` still provides exactly its old interface and body
to every other caller and to direct helper controls. The component does not
modify the VM, native emitter, error classes, observers or default profile.

## Required real validation

`CONTROL-PLAN.json` retains the original complete eight-group matrix, all
orders, assertions and budgets. The original u32 B3 must compile the actual
new source once and the original HIA packer must establish the 1 MiB
aggregate limit before semantic qualification. The current R11 ELF is
1036288 bytes, leaving 12288 bytes; the new machine size is unknown.

Additional paired controls must use actual verified old/new Core and all
real before/after buffers. They cover equal and unequal digits, partial
views, every reachable first failing load, wrap offsets, alias/overlap,
invalid views, the exact depth boundary and the complete original `f14` and
`f106` callers. Private call traces are retained in full and checked against
the explicit old-to-new correspondence; they are not silently normalized.
Each side invokes the original `_Machine` and real instructions. No host
mock, fabricated Native observation, ignored exception or expected fuel
increase can supply a positive result.

The old R10 cross-target Counted failure stopped in phase 1, function index
13 of 38. The count is not a measurement of the two edited block frequencies
and not evidence that this candidate will complete within 10 million steps.
Full program size, fuel and Native/VM correspondence are pending.

## Authoring-only failure retained

The first static symbolic prover expected a balanced `bool.and` tree while
the authored helper uses a left-associated tree. It stopped before issuing
a proof. Its complete script and original failure output remain. The R2
prover corrects that symbolic expectation and writes to a separate output
directory. Product source, draft HIA and generator bytes did not change.

No new product, generator, compiler, VM, Native, binder or qualification
execution occurred while preparing this package.
