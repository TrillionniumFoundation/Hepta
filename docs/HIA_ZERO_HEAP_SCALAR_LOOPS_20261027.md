# HIA P1: zero-live-payload proof across verified pure scalar cycles

**Source scope:** HIA v1–v6 canonical `hepta.hia_program.verify_program` must
validate the complete typed SSA/CFG, including all blocks/backedges, before
the existing `hepta.hia_heap_bound.analyze_constant_live_heap` is used.

## Closed subcase

The prior heap analyzer applied a DAG-only resource recurrence even when
a function contains no executable heap-capable instruction. It refused
every loop, including scalar-only infinite loops whose HIA live heap
payload is identically zero on every finite execution prefix.

The existing `_function` now returns a **zero live HIA payload byte bound**
before the DAG path only if its signature contains no resource arguments
or results and **every instruction in every verified block** belongs to
the frozen `_ZERO_HEAP_CYCLIC_SCALARS` list. The list contains only
constants, fixed-width integer/bitwise/compare/cast and boolean/select
operations. Calls, allocators, Buffer/Loan/Drop/Memory, effectful hardware,
unknown opcodes and future schema features are not admitted by this shortcut.

Importantly, a loop can run forever or trap. This is **not** proof of
termination, finite VM ticks, bounded CPU/stack/RSS, whole-program resource
management or LLVM refinement. The separate `analyze_static_budget`
still correctly refuses cyclic CFGs when claiming a finite VM tick count.

## Regression cases

`tests/test_hia_zero_heap_loops.py` covers the real canonical verifier and
Python HIA VM for a loop with SSA backedge forwarding, a verified infinite
zero-heap loop whose evaluator stops on its step budget, rejection of
repeated zero-byte allocation/drop inside a loop, rejection of looped
calls even when a callee appears scalar, and retention of the existing
12-byte acyclic owned resource upper bound.

Execute on a full exact checkout:

    python -m unittest tests.test_hia_zero_heap_loops tests.test_hia_heap_bound tests.test_hia_static_budget -v
    python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v

No CI scheduling dependency. No full-checkout in-repo test execution occurred
in the model container. This is a limited *static heap* proof, not a
release qualification. Other P0–P7/P01–P12 blockers remain OPEN.
`whole_project_blockers_closed=false`.
