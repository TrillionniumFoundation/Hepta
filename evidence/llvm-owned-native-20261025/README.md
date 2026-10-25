# Owned-byte LLVM attempts: retain the first failure and the later fix

## Optimized compiler: passed the same fixed protocol

The second source candidate is 8fb1f39c87282c8943edcb5a1bf07e50713502b3.
Its complete receipt is 8fb1f39.v1.json, with all 63 samples retained. The
Hepta source, handwritten Rust source, C driver, protocol, workloads, ordering,
sample count and acceptance thresholds are identical to the first attempt.
Only the compiler and its associated regression tests/documentation changed.
The default data validator accepts this complete, source-bound receipt.

| Kernel | LLVM ns/call | Same-source Rust ns/call | Handwritten Rust ns/call | LLVM / same-source | LLVM / handwritten |
| --- | ---: | ---: | ---: | ---: | ---: |
| full_lifecycle | 1,615.99 | 2,948.22 | 1,667.64 | 0.55151 | 0.98010 |
| constructor_error | 19.75 | 24.49 | 24.14 | 0.81023 | 0.83608 |
| two_stage | 1,569.24 | 1,663.77 | 2,891.19 | 0.93683 | 0.55008 |

The geometric means of the paired ratios are 0.748068 against same-source
Rust and 0.766740 against handwritten Rust. Every individual median paired
ratio is below 1.20 and both geometric means are below 1.10. All measurement
quality gates pass; the largest relative MAD is 4.5653%, on handwritten Rust's
constructor_error. The ratios are recomputed from all seven pairs, with no
outlier removal or selected reruns of individual kernels.

All 784 finite native calls still match their oracle. Actual LLVM allocation
observation remains 7 allocations, 7 frees, 0 live, 1 refusal; the compiled leak
negative control remains 7 allocations, 0 frees, 7 live, 1 refusal and fails as
required. The allocation runtime's nullable result and failure branches remain
present. Independent static review also confirmed that both Rust baselines
retain fallible allocation, and their checksum sums retain checked overflow.

The implementation fix gives internal aggregate/slice returns a fresh result
slot, writes scalar fields individually and skips the no-op empty-buffer drop.
The resulting standard LLVM optimization removes Result aggregate/tag
obstacles, the unobserved constructor-error memset and the full-lifecycle
loop's redundant bounds comparison. Overflow checks are retained. The exact
optimized LLVM used for static diagnosis is 8fb1f39.optimized.ll; generated
application code still comes from the same checked Hepta AST/resource graph.

This passing attempt is specific to the committed compiler, host and finite
profile. It does not retroactively change the first attempt, replace a later
integrated release run, prove whole-language safety/performance, or establish
superiority over every Rust implementation. The performance gate's dynamic
allocator-refusal observer is LLVM-specific; the two Rust baselines' allocation
refusal/cleanup observations are a separate untimed qualification.

## First compiler: not passed

Candidate: fa4f8209e45b98e5b1f4cf42e3c47d657d3249d3.
Protocol: hepta.llvm-owned-bytes-perf.v1, frozen in that commit before timing.
Execution: 2026-10-25 16:48:55–16:50:44 UTC.

The complete, unedited first receipt is fa4f820.v1.json. All 63 samples are
retained. The result is **measurement_inconclusive**, with additional failed
performance thresholds. It is not a release pass. No samples were discarded,
no workload or threshold was tuned after observing results, and no repeat
measurement was performed for this attempt.

### First-attempt results

Ratios are the median of seven paired LLVM / baseline elapsed-time ratios;
they are not ratios of the independently reported medians.

| Kernel | LLVM ns/call | Same-source Rust ns/call | Handwritten Rust ns/call | LLVM / same-source | LLVM / handwritten |
| --- | ---: | ---: | ---: | ---: | ---: |
| full_lifecycle | 2,339.71 | 2,959.57 | 1,777.41 | 0.82860 | 1.33158 |
| constructor_error | 63.33 | 25.39 | 25.06 | 2.51461 | 2.61198 |
| two_stage | 1,682.91 | 1,553.88 | 2,889.23 | 1.09064 | 0.58861 |

The geometric mean is 1.31472 against same-source Rust and 1.26976 against
handwritten Rust, exceeding the fixed 1.10 maximum. The full-lifecycle ratio
against handwritten Rust and both constructor-error ratios also exceed 1.20.
The two constructor-error Rust series have relative MAD 10.516% and 7.881%,
exceeding the fixed 5% quality limit. Every sample exceeds 50 ms; the shortest
is 190.48 ms. No duration-limit violation occurred.

For the remaining series, relative MAD is: full_lifecycle Rust 3.488%, LLVM
4.979%, handwritten Rust 2.367%; constructor_error LLVM 4.800%; two_stage Rust
4.007%, LLVM 2.850%, handwritten Rust 4.350%. Complete raw timings, order,
process outputs and host load are in the receipt. The shared host remains an
uncontrolled source of noise despite fixed CPU affinity and pausing other
compiler tasks in this session.

### First-attempt correctness and allocation evidence

All four real native libraries passed 196 finite vectors each: 784 calls.
The actual LLVM resource observer reported seven allocations, seven frees,
zero live allocations and one forced second-allocation refusal. The compiled
free-deleted negative control reported seven allocations, zero frees, seven
live allocations and one refusal, and exited unsuccessfully as required.
The strict source-origin API separately rejected the mutated LLVM before
compilation. This is measured native behavior, not a hand-authored LLVM
application fixture.

The complete receipt passes validate_report with require_pass=False. The
default release validator rejects it with “fixed native performance/quality
gates did not pass”. Outer ok cannot conceal the failed raw metrics.

### First-attempt diagnosis, without additional timing

fa4f820.optimized.ll was produced from the exact retained source-derived LLVM:

    clang --target=x86_64-unknown-linux-gnu -x ir -O3 -S -emit-llvm INPUT.ll -o OUTPUT.ll

The optimized constructor_error still contains a memset before free, as well
as aggregate Result phis, extractvalue operations and redundant-looking tag
switches. The tiny noinline/optnone allocation entry retains the actual
fallible allocation contract. Restoring ordinary free semantics alone does
not cause LLVM to eliminate all initialization through this aggregate control
flow. These are concrete optimization leads, not proof of the performance
cause and not permission to remove an observable allocation-refusal path.

The independent handwritten Rust program is one concrete safe Vec/slice
implementation. These results say neither that LLVM is generally faster than
Rust nor that the handwritten implementation is optimal. In particular,
the faster LLVM result on two_stage cannot stand in for the failed
constructor-error or full-lifecycle comparisons.
