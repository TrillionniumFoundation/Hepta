# HIA P1: same-block integer SSA proofs for cyclic live-heap admission

**Base:** PR #273 exact head `1aa90d5a277b97aac92df8d13a2d72c3cad0a8ec`.
**Scope:** a strict extension to the already bounded block-local Owner loop
profile. This does not change the interpreter, native code generator, schema,
SSA/ownership verifier, or the full cumulative allocation/VM-tick policy.

## What changed

The scoped cyclic analyzer previously accepted literal and cast-derived sizes
but refused all arithmetic-produced extents, even for `4 + 5` in the same
block. After canonical `verify_program` checks the complete Core, the
existing typed `_bounded_binary` interval transfer is now reused for
`int.add/sub/mul.checked` and `int.add/sub/mul.wrap`.

The arithmetic result must be derived exclusively from values established
within that same basic block, starting from the full machine-type domains of
the block's verified scalar inputs. Checked arithmetic permits a bound only
when the **entire abstract result** fits the machine type, or for a proven
exact in-range value. Wrapping arithmetic permits either an entirely
nonwrapping result interval or an exactly known pair whose fixed-width result
is folded. Partially overflowing/wrapping intervals are UNKNOWN.

Every allocation still needs a finite nonnegative interval with a strictly
positive maximum at most `2**63-1`, and every normal CFG edge leaves no
owner or local loan live. Source-unverified or foreign opcodes, fallible
allocation, owner transfer across blocks, calls, and v7 chains still refuse.
A trap does not acquire an eventual-destructor guarantee.

## Regression / evidence policy

```sh
python -m unittest tests.test_hia_scoped_alloc_loops \
  tests.test_hia_zero_heap_loops tests.test_hia_heap_bound -v
python -m unittest tests.test_hia_program tests.test_hia_static_budget -v
```

New cases check: actual VM repeated `4+5` allocations (peak 9); dynamic
`u32` plus one in `usize` (maximum 2**32, not a guessed caller value);
an exact 64-bit wrapped sum; and explicit rejection of partially
overflowing/wrapping dynamic intervals. All leave the cumulative allocation
and tick analyzer's cyclic refusal unchanged.

An independent CPython 3.13 replay of the existing interval-transfer
mathematics checked **677,548 finite typed arithmetic containment cases**
over randomized i8/u8 interval samples without a counterexample. This is a
separate arithmetic control, NOT execution of the new exact-head HIA
repository/VM/native tests. The environment cannot locally clone GitHub.

## Remaining open blockers

This establishes only a bound on requested **peak simultaneously live HIA
buffer payload**, not on process RSS, allocator metadata, cumulative allocation
count, execution time, CPU, stack, liveness, general Ownership/Borrow/Provenance,
source-to-Core/LLVM refinement, hardware/DMA/GPU, C/C++ L2-L3 migration or
AI-agent productivity. `whole_project_blockers_closed=false`.
