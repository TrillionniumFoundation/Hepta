# HIA v6 P1: checked shift intervals for live heap-byte admission

**Exact integration base**: two-parent converged HIA v6 commit
`3aa391d1b3f168e266c4d5ae1d7d88231c4df517` (tree
`f325fa2581471a839873b9b0677dede4b7f83065`).

The single canonical `hia_program.verify_program` checks typed SSA, CFG,
resource ownership and effects. Its VM and independent LLVM code generator
already implement `int.shl.checked`/`int.shr.checked`, but the opt-in
`hia_heap_bound.analyze_constant_live_heap` previously discarded these
results as unknown before a subsequent allocation. This did not authorize an
unsafe budget; it blocked valid finite admission.

## Exact transfer rules

- Input intervals must be known machine-width SSA integers. Unknowns never
  become resource upper bounds. Count interval MUST be wholly in `[0,bits)`.
- Left shift: mathematical corner extrema are a sound interval **only**
  if the *entire* interval fits the output type without wrapping. Otherwise
  return UNKNOWN. One exact value+count pair is allowed to fold through the
  existing type-width `_wrap`, matching the VM's shift count checked /
  result wrap semantics. No assumption that `int.shl.checked` traps on
  discarded bits.
- Right shift: signed arithmetic / unsigned logical semantics; corner
  extrema bound the interval. No implicit source unsigned/signed casts.
- Provably invalid constant counts reject with E_HIA_BUDGET_UNBOUNDED.
  Partial invalid/unknown counts remain UNKNOWN and cannot justify an
  allocation. No attacker-provided budget permits overriding this check.
- The canonical Resource IR, verified HIA bytecode, LLVM emitter, VM,
  C/C++ migrators, cross-target ABI, native publisher and proof claims are
  unchanged. New transfer only affects an opt-in abstract range predicate.

## Evidence and tests

- Independent pure arithmetic exhaustive control (4-bit signed and
  unsigned, all value intervals/count intervals): 5,440 combinations,
  3,288 admitted; all admitted abstract bounds contain each concrete
  wrapped-left/arithmetic-right result. This is a standalone mathematical
  control, **not** an execution of the full Hepta checkout.
- New in-repository `tests/test_hia_heap_shifts.py` executes real
  `verify_program`, `execute_program`, `analyze_constant_live_heap` and
  `analyze_static_budget` when run on a complete exact source checkout:
  select 4/16, right shift 20/10, exact unsigned wrap 144, partial wrap
  refusal, unknown input refusal, invalid counts and pure i8/u8 samples.
- Execution of this repository test and Clang/Rust native differentiation
  is **not** claimed until a full checkout is available.

Run from the exact source commit:

```sh
python -m unittest tests.test_hia_heap_shifts tests.test_hia_heap_negation \
  tests.test_hia_heap_intervals tests.test_hia_heap_bound -v
python -m unittest tests.test_hia_program_llvm tests.test_hia_vm_call_depth -v
```

This increment does not prove general source/core/backend refinement, a
Rust-equivalent memory model, global RSS or physical-device qualification.
`whole_project_blockers_closed=false`.
