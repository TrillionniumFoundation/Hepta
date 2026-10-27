# P6 LLVM scalar32 native qualification: frozen protocol v1

This protocol and its implementation must be committed before its first
measurement. Its acceptance thresholds, workloads, repetitions, and sample
count are fixed in tools/qualify_llvm_native.py. There are no CLI overrides
for these values. Any substantive change requires a new protocol identity;
measurements under v1 must not be rerun selectively or have thresholds changed
to turn a failure into a pass.

## Scope

The same checked Hepta source produces a real Rust 1.90 reference library and
a real direct LLVM/Clang library. Both use checked integer arithmetic and
abort on overflow. The three kernels exercise signed recurrence, unsigned
recurrence with multiplication, and conditional accumulation, all with native
loops and PHIs. Each function is homogeneous i32 or u32.

The protocol is Linux x86_64 only. It does not qualify owned/borrowed memory
lowering, general C/C++ migration, whole-language performance, heap allocation
costs, cross-target execution, or backend refinement.

## Gates fixed before measurement

| Criterion | Frozen requirement |
| --- | --- |
| Correctness | Every deterministic oracle case agrees on both real libraries |
| Timed checksums | Rust/LLVM checksums agree within every paired group |
| Sample count | Seven paired groups per kernel, all retained |
| Work per sample | 64 native calls, 1,048,576 loop iterations per call |
| Prewarm | Eight complete native calls in each measurement process |
| Timing boundary | CLOCK_MONOTONIC_RAW around the native call loop only |
| CPU placement | Lowest permitted logical CPU, inherited by native children |
| Minimum sample duration | Every sample is at least 50 milliseconds |
| Noise | Relative median absolute deviation at most 5% for each backend/kernel |
| Aggregate performance | Geometric mean of kernel paired median LLVM/Rust ratios at most 1.10 |
| Individual performance | Every kernel paired median LLVM/Rust ratio at most 1.20 |

The native C harness directly calls the libraries through function pointers.
Python/ctypes is used only for finite correctness cases, outside the timer.
Dynamic loading, process startup, warmup, and report serialization are outside
the timer. Kernel order rotates between groups; Rust/LLVM order alternates.
No samples are discarded, no workload is reduced after observation, and no
best-run result is selected.

The paired time ratio for one group is LLVM elapsed / Rust elapsed. Each
kernel's ratio is the median of its seven group ratios. The aggregate is the
geometric mean of those three kernel ratios. Noise is the median absolute
deviation of a backend/kernel's elapsed samples divided by their median.

## Outcomes and evidence

- passed: correctness, measurement quality, and every performance gate pass.
- performance_failed: valid measurements exceed a fixed performance gate.
- measurement_inconclusive: samples are too short or noisy. Any observed
  performance threshold failures remain recorded, but are not treated as
  statistically established regressions.
- correctness_failed or blocked: preserve the diagnostic and all partial
  samples collected before the failure.

The JSON output records the predeclared protocol and hash, committed source
identity, tool/compiler hashes, generated Rust and LLVM hashes, independent
SSA verification identity, compiled object/library/driver hashes and sizes,
build-operation wall times, environment/affinity, every raw sample, medians,
relative MAD, paired ratios, checksum outcomes, and all failure reasons.
Object files are separate emissions of the same sources; they are not
misrepresented as the link inputs of the measured shared libraries.

Example:

    python3 tools/qualify_llvm_native.py --describe-protocol
    python3 tools/qualify_llvm_native.py \
      --clang /usr/lib/llvm-20/bin/clang --rustc /path/to/rust-1.90.0/bin/rustc \
      --output /existing/directory/llvm-native-v1-first-run.json

The output must be new; previous receipts are never overwritten. Native
temporary files honor TMPDIR and are removed after the report is assembled.
