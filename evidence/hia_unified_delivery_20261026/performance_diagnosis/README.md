# Standalone HIA performance failure and lowering diagnosis

The original complete run belongs to commit
`9fe295e87352295de4b4eb396bda239ceef2a474`. Its unmodified report remains at
`evidence/hia_unified_fixed_20261026/performance.json`. All 63 samples completed,
and the 588 native correctness calls and allocation/leak controls passed.
The result was **measurement_inconclusive**, not performance qualification:
eight of nine kernel/backend groups exceeded the fixed 5% relative MAD limit.
There were also six performance-threshold failures.

| Kernel | Median paired HIA / generated Rust | Median paired HIA / handwritten Rust |
| --- | ---: | ---: |
| full_lifecycle | 1.238994 | 1.235431 |
| constructor_error | 2.603500 | 2.499976 |
| two_stage | 1.002306 | 0.519852 |

These are the recorded, noisy ratios; they are not qualified performance
estimates. In particular, constructor_error was slower in every recorded
pair, which warranted inspecting emitted code rather than attributing the
whole outcome to measurement noise.

## Static diagnosis

The original HIA constructor emitted an observable `calloc` followed by `free`,
even though no HIA operation could read its allocated bytes. Both Rust
constructors retained an allocation-helper call and one last-byte zero store,
but eliminated the bulk zero initialization. Captured disassembly and optimized
LLVM are included. This identifies a concrete lowering cost; it does not prove
that every part of the measured ratio was caused by that cost.

An experiment lowering all allocations to `malloc` plus an explicit memset
was rejected: LLVM 20 combined it back into a new calloc call that lost the
call-site `nobuiltin` protection. Its input and optimized output are retained
as diagnostic data, not qualified compiler artifacts.

## Selected conservative change

The candidate uses malloc only when the **whole verified function** has scalar
parameters and results and every block passes a closed opcode/terminator
whitelist. Any call, byte load, byte store, resource boundary, unknown opcode,
unknown boundary type, or unknown terminator disables the optimization.
Consequently local byte contents cannot be observed or escape. Functions that
read bytes still use calloc. Allocation attempts, NULL handling, storage
ownership, and free calls remain observable, including optimizer barriers.

The original and candidate have identical canonical Core hashes. `summary.json`
records their different backend-file, implementation and LLVM hashes.
`backend.patch` contains the exact compiler change. No benchmark workload,
baseline, sample order, sample count, or threshold changed.

Candidate checks passed: 17 focused tests, 289 host qualification cases,
17 actual AArch64 QEMU cases, allocator and wrong-code controls, and an
untimed 588-call benchmark correctness preflight. The new tests include
poisoned malloc memory, a non-entry-block zero read, real NULL refusal,
live-address accounting and allocation-abort behavior. The separate
`zero_elision_independent_audit` directory contains another agent's adversarial
review.

**No new performance timing was collected for this diagnosis.** A fresh complete
63-sample run on the frozen candidate is still required; a remaining noise or
performance failure must remain nonpassing. No identical physical OOM behavior
between malloc and calloc, Rust superiority, or backend refinement theorem is
claimed.

`replay_static_comparison.py --output /new/directory` recompiles the captured
LLVM to optimized LLVM only. It does not execute native kernels or collect
timings. `manifest.json` binds all retained files. Binaries were not copied.
