# HIA P1/P2: conservative SSA interval heap-byte admission

**Scope:** exact-source stacked engineering on verified HIA program v1–v6.
This extends the existing hepta.hia_heap_bound analyzer; it does NOT add a
language parser, second owner/loan checker, or alternate LLVM backend.
The existing analyze_static_budget(..., max_live_heap_bytes=N) continues
to be the native pre-publication policy gate.

## New finite cases

The opt-in analyzer propagates immutable integer bounds through:
- Verified const and int.add/sub/mul.checked and int.add/sub/mul.wrap.
  Wrapping is exact for known points, or a provably nonwrapping interval.
- Safe int.cast; select with an unknown Boolean condition but *both*
  alternatives having finite upper bounds; exact Boolean operators.
- buffer.len for internally allocated bounded owners. Its possible length
  starts at zero because a previous try_new may have failed.
- Acyclic CFG block arguments and joins: union possible numeric intervals,
  take a maximum per live owner.
- Existing owner move/drop and nested scalar calls remain accounted.

The result remains a finite **requested live byte payload** upper bound.
Cycles/recursion, unknown extents, oversized sizes, unknown future ISA
schemas/opcodes and resource-valued interprocedural boundaries still reject.

## Soundness guardrails

- Boolean values never impersonate integer constants (True == 1 in Python).
- Checked arithmetic with possible overflow loses precision; exact
  overflowing operands fail closed.
- Wrapping arithmetic that might wrap an interval loses precision unless
  exact operands determine the modular result.
- buffer.len following a fallible allocation or owner join produces a
  possible-length interval, not a forged exact maximum. A subsequent
  wrapping computation cannot claim a misleading small bound.
- CFG joins use maxima for possible owner occupancy, not minima, and
  union scalar possibilities.
- New versions/opcodes require explicit review before acceptance.
- C/C++ annotations or self-rehashed claims never narrow Core values.

## Regression and evidence

Execute on an exact complete Hepta checkout:

    python -m unittest tests.test_hia_heap_bound tests.test_hia_heap_intervals \
      tests.test_hia_static_budget tests.test_hia_static_budget_cli \
      tests.test_hia_program -v

Added tests use actual HIA Core verification and interpreter comparison of
peak_bytes for both conditional outcomes, checked arithmetic, allocator
refusal, phi-like block joins, and modular wrapping. Negative cases reject
undersized policy and unknown dynamic/overflow-driven extents.

Local evidence in the restricted execution container: Python 3.13.5
syntax check on exact checked-in test bytes; 6/6 isolated algorithm tests;
5,200,639 random finite interval arithmetic outcome property checks.
These isolated checks used stubbed canonical verification. The exact
repository parser/VM/native suites, pinned rustc/Clang20 and physical
hardware tests have NOT been executed; do not inherit historical results.

No production RSS/allocator overhead, stack use, CPU time, latency,
resource-valued call transfer, general loop invariants, arbitrary C/C++
migration, ABI interoperability, formal whole-language refinement,
GPU/NPU or real hardware safety proof is established.

whole_project_blockers_closed=false
