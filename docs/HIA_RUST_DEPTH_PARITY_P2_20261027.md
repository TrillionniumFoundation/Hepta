# HIA P2: root-inclusive Rust/Python recursive-call budget parity — 2026-10-27

## Exact source / defect

Parent: PR #279 commit `36be00e407dfff8d47bbed29ffccd834f1025480`.
The canonical `hepta.hia_program_runtime._Machine.invoke` refuses a call
**before any entry tick** whenever `depth >= max_call_depth`; the root starts
at depth zero. Its explicit differential fixture passes `max_call_depth=32`.
The Rust scalar oracle erroneously used `depth > MAX_CALL_DEPTH`, granting
an extra frame and misreporting observable step consumption.

For a program recursively invoking itself exactly once per frame:
- Python canonical: 32 admitted frames, 64 ticks, then `budget_exceeded/calls`.
- Old Rust: 33 admitted frames, 66 ticks.
- Repaired Rust: `depth >= MAX_CALL_DEPTH`, 32 frames, 64 ticks.

A finite recursive function with `n=31` enters depths 0..31 and returns.
At `n=32`, depth 32 must be rejected, even if that nested frame would
immediately return. This matches the canonical runtime resource budget,
not a termination or stack-safety theorem.

## Change and regression

Only the existing Rust scalar VM, its direct Rust tests, the existing
Python/Rust VM differential tests and this document are modified.
No new executable verifier, ISA schema, memory model, native backend,
C/C++ migration tool or compiler admission path is introduced. Existing
source/root/exports validation, bounded step counting and false
proof claims are unchanged.

The Rust tests cover `n=0,1,30,31` positive and `n=32,33` refusal,
as well as exact 64-tick unbounded recursion. The opt-in Python comparison
uses the real HIA verifier and Python VM, and requires status, values,
budget code and step count parity.

```sh
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml \
  finite_recursion_respects_root_inclusive_call_frame_limit
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml \
  recursion_is_bounded_independently_of_step_budget
python -m unittest \
  tests.test_hia_rust_scalar_vm.RustScalarVmParity.test_recursive_depth_boundary_and_budget_ticks_match_exactly -v
```

The independent local Python depth/tick state-machine control reproduced
the 32-frame/64-tick boundary; this does **not** substitute for compiling
the exact Rust commit or executing the full Hepta VM integration suite.
The container lacks Rust/Cargo and cannot clone the full GitHub tree.
All exact-head native, whole-language, GPU/physical hardware, broad C/C++,
true Agent A/B and production p99 gates remain open.
`whole_project_blockers_closed=false`.
