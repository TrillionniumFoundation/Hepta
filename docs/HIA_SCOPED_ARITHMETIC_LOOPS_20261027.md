# HIA P1: reviewed interval arithmetic for block-local Owner loops

This increment extends the **existing** `hepta.hia_heap_bound` live-payload proof; it is not a new SSA, verifier or numeric semantics authority. Parent source: PR #274 exact HEAD `fbf6abdc7156187c962544c3261a577ab81b3c30`.

## Specific prior rejection

The scoped Owner-loop proof already recognized single-block constants and checked casts. A valid program that checked-cast a loop counter to `u8`, widened to `usize`, computed `size = base + 3` with `int.add.checked`, allocated exactly `size` bytes and dropped the sole Owner before every loop edge was rejected despite the existing DAG analyzer having a sound interval transfer for the same operation.

## Implementation

Reuse **the same existing** `_bounded_binary` (no copied implementation) to propagate six arithmetic opcodes within one verified basic block: `int.add/sub/mul.checked` and `int.add/sub/mul.wrap`. The values must already be established by literal constants, intrinsic typed bounds or checked/wrapping cast transfer in that same block. Partial modular wrap, any interval that can overflow, unknown SSA or unsupported opcodes do not mint a size upper bound; the cyclic resource analysis rejects if a `buffer.new` depends on them. An exact pair of wrapping operands can use the existing exact modular fold.

Still require scalar-only block/function parameters, **no Owner across any normal CFG edge**, no fallible `try_new`, calls, FFI, memory operations or unsafe effects; all Owner creations and drops must balance by each ordinary terminator. The canonical `hia_program.verify_program` remains mandatory before analysis.

## Qualification and evidence

`tests.test_hia_scoped_arithmetic_loops` exercises actual HIA verifier, byte-Owner VM and optional live-payload admission with a checked u8→usize widen+3 (peak ≤258), widened multiplication by four (peak ≤1020), exact wrapping 250+10→4, rejected uncertain u8 wrap/overflow, actual dynamic VM samples and trap input 256.

Independent local Python 3.13.5 mathematical interval containment control: **421,680** sampled evaluations from **60,240** accepted interval/operator cases across i/u8/16/32/64; no counterexample observed. This is a pure model control, **not** full HIA verifier/VM, Cargo or LLVM acceptance. The new test module syntax-compiled locally, but full exact-HEAD in-repository test execution, native compiler, platform, agent and formal qualification remain unexecuted.

Reproduce on a complete checkout:

```sh
python -m unittest tests.test_hia_scoped_arithmetic_loops tests.test_hia_scoped_alloc_loops tests.test_hia_heap_bound -v
python -m unittest tests.test_hia_program tests.test_hia_program_llvm tests.test_hia_static_budget -v
cargo test --manifest-path rust/hia-core-shadow/Cargo.toml
```

**Claims remain limited to requested live HIA Owner payload bytes.** No finite cumulative allocations, VM steps, termination, process RSS/CPU, source→Core refinement, LLVM/backend correctness, physical GPU/DMA, broad C/C++ L2/L3 or real-Agent A/B claim follows. `whole_project_blockers_closed=false`.

## Existing regression rebaselining

The earlier `tests.test_hia_scoped_alloc_loops.test_unproved_arithmetic_extent_still_rejects_on_cycle` had hardcoded a refusal for the now-reviewed `u32 → checked usize → +1` arithmetic case. It is updated to assert the mathematically conservative upper bound `2^32` requested bytes and verify finite VM observations, while `analyze_static_budget` continues to refuse cyclic tick/allocator *count* proofs. Otherwise the newly supported semantics would falsely fail the existing acceptance suite.

Additional positive tests cover checked or nonwrapping `usize` subtraction with peak bound 260 and nonwrapping modular multiplication with bound 1020; uncertain partial modular wrapping remains a negative case. These are committed **test inputs**, not test runs on a full Hepta checkout.
