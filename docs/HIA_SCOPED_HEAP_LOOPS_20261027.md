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
  memory access, FFI, arbitrary allocator or future opcode.
- Each `buffer.new` uses an exactly typed, strictly positive `usize`
  `const` emitted **earlier in the same block**, no interblock or inferred
  SSA size, not even one derived from a checked cast.
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

## Tests committed

`tests/test_hia_scoped_alloc_loops.py` exercises the existing canonical
HIA verifier and VM with actual finite loop executions, verifies a 9-byte
cycle independent of iteration count, a 13-byte concurrent local owner peak,
and that independent 3-/9-byte scopes take a maximum instead of a sum.
Negative tests cover fallible owner loops, unknown dynamic sizes, escaped
owner block arguments, unrecognized calls, and the independent static-budget
cyclic refusal.

Execute against the **exact repository snapshot**:

```sh
python -m unittest tests.test_hia_scoped_alloc_loops tests.test_hia_zero_heap_loops tests.test_hia_heap_bound -v
python -m unittest tests.test_hia_program tests.test_hia_static_budget -v
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
