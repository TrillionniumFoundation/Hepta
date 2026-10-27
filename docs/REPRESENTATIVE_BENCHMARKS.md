# Representative native kernel measurements in v0.2

This suite compares four algorithms beyond the initial sum/copy examples using
four native implementations. The authoritative numeric results are in
[`artifacts/representative-benchmarks.json`](../artifacts/representative-benchmarks.json).
Read them with the compiler/source identities recorded in that report. Earlier
development-branch timing tables and function-size numbers are not carried
forward as measurements of a different v0.2 source snapshot.

## Implementations and contracts

| Report name | Source and compilation path |
|---|---|
| `hepta_rust` | [`representative.hepta`](../benchmarks/representative.hepta), checked and emitted by Hepta, then compiled by rustc |
| `rust` | Independently handwritten [`representative.rs`](../benchmarks/representative.rs), compiled directly by rustc |
| `hepta_c` | The same checked Hepta program lowered directly to C11 and compiled by GCC |
| `hepta_c_unroll` | The identical generated C with the explicit `unroll` optimization profile (`-funroll-loops`) |

The primary comparison, `hepta_rust` against `rust`, uses the same Rust compiler,
target and default target CPU, optimization level 3, overflow checks enabled,
panic abort, one code-generation unit, and no link-time optimization. The
handwritten baseline is not generated from Hepta's emitted Rust. Compiler
versions, flags, commands, generated-source identities, and artifact identities
are recorded where each build path exposes them.

All four implementations have the same external C calling convention and
raw-pointer caller obligations. Kernels allocate nothing, and the driver
allocates outside timed regions. The dot product and FNV computation use
explicit modular arithmetic. These kernels measure a raw-pointer, allocation-free
core; they do not measure owned-buffer APIs, compile-time borrow analysis,
channels, task groups, allocator behavior, or application-level AI-agent
workflows. Safe borrowed-slice execution is checked separately by the native
test suite.

The independent C path does not invoke rustc. Its GCC optimizer, code generation,
and compiler-specific checking machinery differ from the Rust path, so a timing
difference cannot be attributed solely to language syntax. There is no separate
handwritten C baseline in this suite.

## Algorithms and correctness checks

[`representative_driver.c`](../benchmarks/representative_driver.c) validates each
executable's output before measuring it:

| Kernel | Work and reference check |
|---|---|
| FNV-1a | Hash the input bytes; compare with the driver's direct reference computation |
| Histogram | Clear and fill 256 bins, then compute a weighted checksum; compare every bin as well as the checksum |
| Modular `u64` dot product | Multiply corresponding elements and accumulate modulo 2^64; compare with the driver's direct reference computation |
| Binary-search batches | Find lower bounds in a sorted table containing duplicates and gaps; compare with an oracle that sorts queries and performs a linear merge |

The correctness lengths are 1, 3, 31, 255, 257, and 4,099, covering short inputs,
tails, and bin boundaries. Four implementations, four kernels, and six lengths
produce 96 correctness invocations. The driver also checks zero-length inputs
and empty query batches. These checks can catch mismatched answers and edge
behavior; they are not proofs for every input or proof that unsafe caller
obligations are satisfied in arbitrary applications.

## Reproduction and measurement method

```sh
python tools/benchmark_suite.py --output artifacts/representative-benchmarks.json
python -m unittest discover -s tests -p test_representative.py -v
```

Use the pinned Rust compiler through `RUSTC` when it is not already discoverable.
The harness also needs native GCC and the object tools used by the validation
scripts. `--correctness-only` runs correctness without timings; its output must
not be presented as a performance run. `--trials` changes the number of trials
and must be at least three.

The default configuration uses seven trials for each of two sizes, 4,096 and
262,144 input elements. Implementation order is randomized with seed 20261024;
execution is pinned to one available CPU when affinity and `taskset` are
supported. Four kernels, two sizes, four implementations, and seven trials
produce **224 timing samples**. The first three kernels are reported in
nanoseconds per element; binary search is reported in nanoseconds per query.
Sample count and units must be taken from the actual report if options change.

All raw measurements are retained, including slow samples. Each summary contains
minimum, median, and maximum times. Ratios divide an implementation's observed
median time by the independently handwritten Rust median for that kernel and
size. A ratio above 1 means an observed slowdown; below 1 means a shorter
observed time. `measurements.all_observed_slowdowns` retains every ratio above 1
without claiming statistical significance.

## Explicit C loop optimization

The default C flags remain unchanged. `hepta build/run/check --backend c
--c-opt unroll` selects a separately identified optimization profile. Both the
native checking compilation and the final artifact use that selection. Invalid
profiles, use with the Rust backend, and combining `unroll` with disabled
optimization fail explicitly. The profile enables ordinary compiler loop
unrolling; it does not remove overflow/bounds guards, enable fast-math, infer
restrict/no-alias contracts, or change the language's modular arithmetic.

The previous modular dot slowdown was reproduced as scalar GCC output. In an
exploratory comparison, both a relaxed vectorization cost model and loop
unrolling improved that kernel; their effects on histogram/search differed.
The accepted optional profile uses only `-funroll-loops`. The suite retains the
default C baseline, includes the unrolled variant in **all** kernels/sizes, and
reports every slowdown for it too. No benchmark winner is selected per kernel
at runtime. GCC documents that [loop unrolling increases code size and may or
may not improve performance](https://gcc.gnu.org/onlinedocs/gcc-13.4.0/gcc/Optimize-Options.html#index-funroll-loops).
This is an exposed and measured tradeoff, not a guarantee that all C output
matches or beats Rust. The complete unchanged-source release run is the source
for current measurements; exploratory numbers are not substituted for it.

## Reading the release report

Before quoting a v0.2 result, check that the report has `status: passed`, that
`measurements.status` is `completed`, and that the recorded compiler and fixture
hashes match the source snapshot being discussed. The harness rejects a run if
the compiler sources change during measurement. Release validation refreshes
the report for its fixed source snapshot; an older report remains evidence only
for its recorded inputs.

The `function_bytes` section compares the emitted function text sections for
`hepta_rust` and handwritten `rust`, including their byte counts and hashes. If a
particular pair is identical, that establishes equality of those extracted
sections for that build. It does not establish complete-object or relocation
equivalence, or equal measured latency in separate executables. If `objcopy` is
unavailable, the section reports that this comparison was not run.

Shared-host load, frequency variation, cache state, and executable context are
not fully controlled. The harness does not compute confidence intervals or
perform a statistical significance test. Retain slower rows when summarizing
the report, and treat a regression as an observation to investigate. Four small
kernels cannot establish Rust-level performance generally, language-wide speed
superiority, production workload coverage, or AI-agent coding effectiveness.

These are native-host measurements. The separate
[AArch64 cross-execution report](../artifacts/cross-execution.json) records actual
sum/copy execution under QEMU with a Rust `no_std` syscall harness and a negative
control. It provides no physical-hardware timing or independent AArch64 C ABI
measurement. See [C interoperability](C_INTEROP.md) for the distinct host ABI,
cross-compilation, emulated execution, and hardware qualification boundaries.
