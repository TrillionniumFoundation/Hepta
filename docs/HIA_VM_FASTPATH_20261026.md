# P5 HIA v6 bounded VM memory fast paths (2026-10-26)

This is an optimization of the **existing Python interpreter helper** only. The single canonical HIA Program verifier, resource/borrow operations, LLVM emitter and target machine semantics are not changed. Full Hepta native qualification remains open.

## Changes

* `fill_bytes` allocates a pattern of at most 4096 bytes, writes it once, then doubles the initialized range through strictly disjoint `memoryview` copying, reducing Python loop iterations from O(count / 4096) to O(log count).
* `move_bytes` detects provably nonoverlapping ranges and uses a direct `memoryview` assignment. Forward and backward overlapping cases retain the existing <=4096-byte per-chunk memmove copy.
* All offsets/lengths and scalar values undergo complete strict validation **before** any mutation, including zero-length and boundary requests. No C foreign call, unverified pointers or new allocator authority.

## Executed local checks

The unmodified upstream baseline was reconstructed byte-for-byte from Git Blob `ee7006b87992cee22e10fde0b01ddf62d0321760`; a Python comparison reconstructed that exact Blob SHA. The optimized source and extra tests have likewise been locally syntax/runtime checked. On CPython 3.13.5, **5 original helper tests** and **4 additional tests** passed without skips, including randomized reference differential, actual host libc memmove/memset comparisons in the original suite, and strict before-mutation error rejection.

An exploratory paired Python microbenchmark (9 samples/arm; 2 warmups; fixed bytes; 4MiB buffer; order alternates) on a nonexclusive shared Linux container observed:

| 4MiB operation | Baseline p50 | Optimized p50 | Optimized/baseline |
| --- | ---: | ---: | ---: |
| Fill full buffer | 0.172 ms | 0.083 ms | 0.48 |
| Move 2MiB nonoverlap | 0.236 ms | 0.048 ms | 0.21 |
| Overlap left | 0.477 ms | 0.472 ms | 0.99 |
| Overlap right | 0.491 ms | 0.495 ms | 1.01 |

Tracemalloc temporary-allocation peaks were ~4.8KiB for fill, ~0.5KiB for nonoverlap copy and <5KiB for overlapping copy. Input buffers were created outside tracing. Measurements are descriptive, not production p99/CPU/RSS, whole interpreter latency, LLVM native speedup, or a statistically controlled machine comparison.

Reproduce the safety tests on the **exact committed** source:

```sh
python -m unittest tests.test_hia_bounded_memory tests.test_hia_bounded_memory_fast -v
python -m unittest tests.test_hia_program tests.test_hia_range_fill_v6 tests.test_hia_program_llvm -v
```

The first line has local subset execution evidence. The full in-repository exact-commit LLVM/Rust tests in the second line were **not run** in this local restricted checkout. P0–P7 production blockers remain OPEN/PARTIAL; `whole_project_blockers_closed=false`.
