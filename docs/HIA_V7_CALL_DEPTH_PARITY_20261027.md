# HIA P0/P2 v7: root-inclusive call-depth and Rust shadow alignment — 2026-10-27

## Real mismatch in the v7 integration line

Parent is PR #282 `0dd3d212a3d01a1f69b075dddc1519d987219e7d`,
which integrates the v1–v6 Rust scalar oracle into the separate v7
executable Core. The inherited v7 Python interpreter used
`if depth > self.max_call_depth`, allowing one **extra** call frame.
However the same exact v7 tree's `hia_static_budget._bound_function`
reports `max_call_depth=1` for a root-only call, `2` for a root+child,
and exposes that number as the policy upper bound. A runtime accepting a
root+child at limit 1 violates this shared root-inclusive contract.

The v6 branch already fixed that Python runtime error and has
`tests/test_hia_vm_call_depth.py` enforcing root-inclusive semantics,
but the v7 branch had not inherited either its runtime correction or test.

## Implemented

1. V7 Python `_Machine.invoke` refuses when `depth >= max_call_depth`,
   *before* ticking or executing the next frame.
2. Reuse the exact corrected v1–v6 Rust `scalar_vm.rs` Git blob from
   PR #280; it uses the same root-inclusive `>=` rule. Rust v7 programs
   remain unsupported by its scalar verifier, **not silently accepted**.
3. Preserve v7's extra version/refusal/export tests while correcting the
   old 66-tick/33-frame Rust and Python differential assumptions to
   64-tick/32-frame. Add finite Rust boundaries `n=31` success,
   `n=32` refusal.
4. Import the existing canonical Python-only
   `tests/test_hia_vm_call_depth.py` unchanged and add explicit
   v7-schema static-vs-dynamic one/two-frame and recursive budget tests.
5. No alternate parser/verifier, ABI, LLVM, resource SSA, C/C++ migrator,
   front-end schema or publication authority is introduced.

### Acceptance commands on the exact combined SHA

```sh
python -m unittest tests.test_hia_vm_call_depth tests.test_hia_v7_call_depth -v
python -m unittest tests.test_hia_static_budget tests.test_hia_rust_scalar_vm -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
python -m unittest tests.test_hia_program tests.test_hia_program_llvm -v
```

An independent Python control checked every root-inclusive frame bound 1..256,
with 3/3 test groups passed. This does **not** claim actual complete repository
VM tests, Rust/Cargo native execution or the v7 Core LLVM differential were
run in this limited container; Cargo and a full GitHub checkout are absent.
CI queue state is not a development stop, nor proof of pass.

Still OPEN: broad v7 Memory/Provenance SSA, source-to-native refinement,
C/C++ L2/L3, real model Agent A/B, GPU/physical DMA/IRQ, sustained p99 and
production qualification. `whole_project_blockers_closed=false`.
