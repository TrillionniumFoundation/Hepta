# HIA P1: bounded live bytes in strictly block-scoped allocating CFG cycles

**Status:** implementation candidate, not generalized loop/resource soundness.
**Base:** integrated P1/P7 PR #271 at exact `a686c56f469ee44ce1cbde48ccef7ad9b71d33c5`.
**Authority:** `hepta.hia_program.verify_program` validates every byte of the
executable SSA/CFG and all owner/loan transitions *before* this analyzer runs.
No duplicate ownership checker, LLVM emitter or C/C++ migrator is added.

## Verified invariant and scope

The existing `hepta.hia_heap_bound.analyze_constant_live_heap` is extended
for a narrowly recognized *cyclic* profile:

- Every function/block parameter and return is scalar; no Buffer/Loan enters
  or exits a block over any CFG edge.
- Instruction vocabulary is frozen: pure scalar operations plus
  `buffer.new`, `owner.move` and `owner.drop`. No calls, borrow,
  memory access, FFI, arbitrary allocator or future opcode. Scalar arithmetic
  can affect control flow but does not create a new allocation-size proof
  unless the existing bound transfer explicitly covers the operation.
- Each `buffer.new` uses a nonnegative `usize` extent whose upper bound is
  **strictly positive** and at most `MAX_REQUEST`, proved within that block
  from exact integer constants, intrinsic width bounds on its block-local
  scalar parameters, or the already implemented trap-aware `int.cast`
  interval transfer. No unreviewed arithmetic result, caller assertion or
  interblock bound is accepted.
- A checked narrowing cast may trap for out-of-domain inputs; its successful
  continuation can still have a finite destination-type interval. Wrapping
  casts use only the previously audited bounded small-domain policy.
- Each ordinary block exit has **no outstanding owned buffer**. Each local
  move preserves the same measured extent, and each drop subtracts precisely
  its recorded extent. A `trap` may retain owners because execution stops;
  no normal cleanup after abort is claimed.
- The analyzer refuses fallible `buffer.try_new` and all resource-bearing
  PHI/block arguments in this profile, retaining historical rejection rather
  than silently expanding its proof.

Let `L_b(k)` be the sum of requested live owner payload bytes after
instruction prefix `k` in basic block `b`. Every normally taken CFG edge
starts/ends with `L = 0`; therefore a full execution, regardless of the
number of backedges, has HIA live-payload peak at most:

`max_b max_k L_b(k)`.

This is an inductive **live-payload** bound only; it is not a bound on
**cumulative** allocations, allocator failure, fragmentation, runtime
metadata, physical RSS, CPU time, steps, stack, termination, total I/O or
hardware availability. `analyze_static_budget` keeps rejecting these cycles
when asked for finite allocation-interaction/tick ceilings.

## Failure behavior

If the normal DAG procedure finds a cycle, the new narrow checker is only
consulted for the existing `E_HIA_BUDGET_UNBOUNDED` diagnostic. Any
unrecognized operation, missing exact size, resource-bearing block argument,
live owner on an ordinary edge, call or fallible allocation leaves that same
**failure** in force. A scalar-only loop still uses its preexisting zero-byte
proof; all acyclic programs retain the existing full interval-aware analyzer.

## Explicit live-heap-only policy admission

`qualify_live_heap_budget(program, max_live_heap_bytes=N)` adds a scoped,
standalone, typed admission API (strict integer N in 0..2^63-1). It **reverifies**
the complete canonical HIA Program, computes existing immutable-program live
payload bounds, then refuses functions whose upper bound exceeds N. The
returned receipt binds the canonical Core SHA and does **not** assert source
origin, native backend refinement, process RSS, allocator interactions, VM
ticks, termination or whole-language soundness.

This is intentionally **not** wired into the existing full finite
`analyze_static_budget` qualification or presented as a native execution
authorization. A cyclic program can satisfy a maximum *simultaneously live*
payload policy while requiring an unbounded total number of allocations.
These remain distinct safety/resource contracts.

## Tests committed

`tests/test_hia_scoped_alloc_loops.py` exercises the existing canonical
HIA verifier and VM with actual finite loop executions, verifies a 9-byte
cycle independent of iteration count, a 13-byte concurrent local owner peak,
and that independent 3-/9-byte scopes take a maximum instead of a sum.
Additional positive tests bind variable u32/u8 narrowing-cast extents from
the language's full machine type domains, then compare actual VM peaks.
Negative tests cover fallible owner loops, unreviewed arithmetic sizes, escaped
owner block arguments, unrecognized calls, and the independent static-budget
cyclic refusal.

## Optional independent P2 native differential

`tests/test_hia_scoped_alloc_native.py` adds real checked-HIA
Program -> existing LLVM emitter -> actual Linux x86-64 Clang20+ shared
library -> C ABI call comparisons against the existing HIA Python VM for
the finite scoped-buffer fixtures. It requires a **real native compiler** and
is explicitly skipped without it; a skipped test is not evidence.
Compiled-return parity alone cannot prove actual allocator/free events.
No Rust/AST fallback, C/C++ migration, target cross-execution or whole-program
backend refinement is claimed.

Execute against the **exact repository snapshot**:

```sh
python -m unittest tests.test_hia_scoped_alloc_loops tests.test_hia_zero_heap_loops tests.test_hia_heap_bound -v
python -m unittest tests.test_hia_program tests.test_hia_static_budget -v
python -m unittest tests.test_hia_scoped_alloc_native -v
```

The current external editing environment cannot clone github.com or run a
complete checkout; unexecuted repository-native tests are **not** claimed
passing. No CI queue status is used as a development stop signal.

## Remaining blockers

Nonconstant but provable dynamic allocations inside CFG cycles, cross-block
owner/loan invariants, loop calls, fallible allocation, arbitrary C/C++ L2/L3,
general source-Core-native proof and cross-target runtime, real Agent A/B,
physical IRQ/DMA/GPU/NPU qualification, sustained production p99 remain
**OPEN**. `whole_project_blockers_closed=false`.
