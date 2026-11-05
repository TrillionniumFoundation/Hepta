# Ordered raw-store calls

## Observed baseline, retained separately

The first checkpoint of #610 changed no compiler implementation and retained
C's E_C_BACKEND_EVALUATION rejection for effectful raw-store operands. At exact
commit `7ccabfaf98528a021fbb904136cef19d2d00ae63`, actual Rust 1.90 on both
[Linux x86-64](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41669576106/job/126034053668)
and [AArch64](https://github.com/TrillionniumFoundation/Hepta/actions/runs/41669576106/job/126034052674)
passed all four baseline characterization controls, with no skips/xfails.
Those commits and runs remain evidence of the pre-fix defect, not qualification
of this subsequent source.

SPEC section 7 specifies left-to-right named-call argument evaluation; the
checker visits raw store arguments in pointer, offset, value order. The old
Rust emitter used `*pointer.add(offset) = value`, but Rust
[assignment evaluates the assigned value first](https://doc.rust-lang.org/reference/expressions/operator-expr.html#assignment-expressions).
Actual store execution produced VPIA and cells 0/42, rather than the ordered
oracle's PIVA and cells 42/0. Volatile store already followed call order.

P is pointer selection, I is offset, V is value, A is the next operation. V
changes which of two valid, aligned i64 cells a later pointer selection returns.
Thus the trace also changes the actual destination, not just a commutative
counter. Aborts at P/I/V observed VP/VPI/V in old Rust store, versus the intended
P/PI/PIV. Each process starts fresh; stdout is flushed before each abort.

## Repair and qualification scope

Rust store now evaluates the three operands in one ordered tuple binding inside
a fresh block, then writes using those values. Ordinary assignment remains
right-hand-side-first. Nested stores have separate lexical temporaries; source
short-circuiting remains intact. Volatile Rust lowering is unchanged.

The C emitter already materializes each raw-operation operand into a separate
statement. Remove only its extra effectful-operand rejection for store and
volatile_store. Named-place indexing retains its existing conservative effect
restriction. The checker still requires unsafe, mutable pointers for stores,
and integer pointees of at most 64 bits for volatile access.

Tests run real C and Rust O0/O3 executables with a foreign helper. C uses UBSan.
Besides normal and foreign-abort traces, controls cover nested stores, both
executed/skipped short-circuit directions, and actual Hepta assert(false) in
each operand, plus a plain-name index snapshotted before a later value operand
mutates that index. Existing ordinary-assignment resource-order tests remain in the
CI lane. All 25 unique tests must execute without skip, xfail or xpass.

No raw-pointer safety is established: validity, bounds, alignment, lifetime and
allowed access remain the unsafe caller's obligations throughout evaluation.
This is not MMIO, concurrency, volatile-order hardware qualification, or a
change to ownership rules. Local Rust is unavailable; the new source still
requires its own exact-head hosted Rust validation.
