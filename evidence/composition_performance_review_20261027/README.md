# Independent retained-performance review: resource composition candidate

## Result and scope

Both frozen performance qualifications remain **`measurement_inconclusive`**.
The independent review reproduces all **42 scalar and 63 owned samples**, every
paired ratio, all per-backend medians/MADs, and the original failure conditions.
Scalar has one relative-MAD failure; owned has five. All original paired-time
ratio thresholds pass, but that does not override a measurement-quality failure.

Candidate: `3a424e427b378400802c9e3c2fef558c0a352756`.
Baseline for protocol/source comparison: `bdb8690` (full identity in `review.json`).
Compiler tree SHA-256: `baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7`.
Process observer SHA-256: `855c4716b4c10e20e6844942667c940494eee834bd421718898a66f7cb95847c`.

This review runs **no native program, compiler, observer, benchmark or timing
experiment**. It does not call either production `evaluate_samples` function.
It reads immutable Git objects and complete retained reports, reconstructs the
fixed sample order, uses exact fractions for medians/threshold comparisons,
and independently checks each observation's identity, counter arithmetic,
raw-counter digest and explicit unavailable/reset status.

The two complete producer logs were already present before review. The release
collector writes these logs after the corresponding producer subprocess returns.
Both reports have `phase=complete`, a finished timestamp, and stable repeated
reads. This review does not reinterpret a failed producer as a release pass.
It covers arithmetic, input identities and retained observations; it does not
repeat the full correctness/ABI/source-to-machine-code qualification and does
not authenticate arbitrary third-party claims.

## Input identities

The original full reports and execution artifacts are archived separately by
the integrating collector. This directory contains derived review evidence,
not replacement copies of those originals.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| scalar | 304972 | `03afde9b3c151bbbd2ef1117b376f3b7375ec2fd7629ab8583a38ffe698af381` |
| owned | 536076 | `ee9320e2117fbc285fd9c73dcda58b6f6aff9e90867012725fd382faff9fafa7` |

The producer paths, terminal-log hashes, start/finish timestamps and full input
bindings are retained in [review.json](review.json). No source report was modified.

## Frozen protocol comparison

The comparison reads both commits through `git show`, with no checkout change.
Both `PROTOCOL` definitions and both `evaluate_samples` bodies are byte-identical.
The owned `PROFILE`, `CALLS` and `SIZES` references are also statically resolved;
the resulting protocol values are identical. The scalar source/driver and owned
sample-order function, all five owned workload/reference/driver/observer files,
and the owned performance protocol document remain unchanged.

| Protocol | Canonical JSON SHA-256 |
| --- | --- |
| scalar | `4e688e468819eb317043fb94db6834ec790c4da98c1956d60bc7ec357d65ed89` |
| owned | `af27b7f8758bd95623f4748e356dff542e063141669e586205d295b6d65dda51` |

The scalar schedule remains seven groups, three rotating kernels, and alternating
Rust/LLVM order. Owned remains seven groups, three rotating kernels, and the
original rotating/reversing order of Rust, LLVM and handwritten Rust. All samples
remain present in their original order. The fixed requirements remain:

- Minimum native duration: 50,000,000 ns; owned also has a 30,000,000,000 ns maximum.
- Relative MAD: at most 0.05 for every kernel/backend.
- Median paired LLVM/baseline ratio: at most 1.20 for every kernel/baseline.
- Geometric mean of the three paired medians: at most 1.10 for each baseline.
- No clipping, retries, calibration or selection of a more favorable run.

## Complete median/MAD results

Times below are integer nanoseconds. Percentages are displayed to nine decimal
places; `review.json` includes exact reduced fractions. Threshold decisions use
those exact fractions, not rounded display values.

| Profile | Kernel | Backend | Median ns | MAD ns | Relative MAD % | Quality |
| --- | --- | --- | ---: | ---: | ---: | --- |
| scalar | signed_walk | rust | 700871205 | 15413813 | 2.199236164 | pass |
| scalar | signed_walk | llvm | 688396148 | 15132064 | 2.198162213 | pass |
| scalar | unsigned_walk | rust | 1044022333 | 25353777 | 2.428470752 | pass |
| scalar | unsigned_walk | llvm | 1014974573 | 16608525 | 1.636348874 | pass |
| scalar | branch_accumulate | rust | 537404028 | 44730751 | 8.323486366 | FAIL |
| scalar | branch_accumulate | llvm | 556725896 | 24420592 | 4.386465975 | pass |
| owned | full_lifecycle | rust | 1841069119 | 108514511 | 5.894103045 | FAIL |
| owned | full_lifecycle | llvm | 1816351471 | 92705483 | 5.103939655 | FAIL |
| owned | full_lifecycle | handwritten_rust | 1875420615 | 121644881 | 6.486271934 | FAIL |
| owned | constructor_error | rust | 219490947 | 9789046 | 4.459885992 | pass |
| owned | constructor_error | llvm | 181455129 | 11422745 | 6.295079705 | FAIL |
| owned | constructor_error | handwritten_rust | 220486409 | 23403955 | 10.614692809 | FAIL |
| owned | two_stage | rust | 1599577025 | 39009652 | 2.438747956 | pass |
| owned | two_stage | llvm | 1728850881 | 54983856 | 3.180370071 | pass |
| owned | two_stage | handwritten_rust | 2941225770 | 90965977 | 3.092791377 | pass |

All 105 native durations satisfy their original minimum/maximum-duration gates.
The six failures in the table are the complete quality-failure inventory.

## All paired ratios

Each ordered list below contains groups **0 through 6**, with no omitted group.
Every value is LLVM elapsed divided by that group's baseline elapsed. The exact
fractions, native samples and sample identities are retained in `review.json`.

**scalar / signed_walk / rust** — median `0.9912044097577467`.

```json
[0.7948231666202674, 1.0220068580721353, 0.9521404377102172, 1.152688056503674, 0.9476310867080009, 1.0304594251378896, 0.9912044097577467]
```

**scalar / unsigned_walk / rust** — median `0.9838211511719517`.

```json
[0.9424181374035826, 1.011412637208587, 1.0609865239348286, 0.8634698210960408, 0.9335967380082953, 0.9838211511719517, 1.0183092891886787]
```

**scalar / branch_accumulate / rust** — median `1.0116824819997545`.

```json
[0.9392460210588522, 1.0205272077069727, 1.130010337459403, 0.9624153617072205, 0.9952060115265674, 1.0116824819997545, 1.0272861520103027]
```

**owned / full_lifecycle / handwritten_rust** — median `0.9745953299121648`.

```json
[1.05541321605112, 0.8182640149917761, 0.9745953299121648, 0.9694010341780784, 0.9797158338477002, 1.0026282327798026, 0.9733612241733494]
```

**owned / full_lifecycle / rust** — median `1.048366073203737`.

```json
[1.090156408140966, 0.9762687492016968, 1.0766999816463203, 1.048366073203737, 0.9988818706898334, 1.0782599225189895, 0.8958203286241148]
```

**owned / constructor_error / handwritten_rust** — median `0.8469986272852073`.

```json
[0.605982356563472, 0.7293624722015875, 0.9083153251903616, 0.7027166625431254, 0.9109902263650906, 0.8915576878028795, 0.8469986272852073]
```

**owned / constructor_error / rust** — median `0.8770590366606009`.

```json
[0.6285467645422853, 0.8811028137757317, 0.8770590366606009, 0.7415927651393465, 0.9119530701708123, 0.8862262840693673, 0.8487752794247816]
```

**owned / two_stage / handwritten_rust** — median `0.5755331458545243`.

```json
[0.5928299030237315, 0.5150955580399882, 0.5822796259241911, 0.560555061541612, 0.5715062504118971, 0.6066505618650112, 0.5755331458545243]
```

**owned / two_stage / rust** — median `1.0293854003507954`.

```json
[1.0218225447638938, 1.1190489760989948, 1.00530748002562, 0.9798966336116262, 1.0293854003507954, 1.1787256729991882, 1.0790075138454371]
```

### Geometric means

| Profile | Baseline | Independent geometric mean | Original threshold |
| --- | --- | ---: | ---: |
| scalar | rust | 0.995499860612021 | 1.10 |
| owned | handwritten_rust | 0.7802955394505982 | 1.10 |
| owned | rust | 0.9818382113054538 | 1.10 |

The independent calculation takes the cube root of the exact rational product;
the producer uses `exp(mean(log(...)))`. Their floating results agree within
relative `1e-14` and absolute `1e-15`; the owned Rust result differs in the last
binary rounding place. Threshold decisions compare the exact product to
`(11/10)^3`. This numerical implementation difference does not change a result.

## Observation identity, availability and limits

Every sample has exactly one complete process-observation row with the matching
sample index, group, kernel, backend, full command and frozen scope. Monotonic
intervals are ordered; every wall delta equals end minus start. All 105 observed
wall intervals enclose the retained native duration. Observations do not replace
or adjust a native elapsed value.

| Source | Scalar observed / unavailable | Owned observed / unavailable | Missing-data handling |
| --- | --- | --- | --- |
| RUSAGE_CHILDREN | 42 / 0 | 63 / 0 | Actual six-counter differences retained |
| Visible cgroup cpu.stat | 42 / 0 | 63 / 0 | Raw text hashes and integer differences replayed |
| Visible cgroup cpu.pressure | 0 / 42 | 0 / 63 | Every before/after snapshot has FileNotFoundError, errno 2; counters and delta stay null |
| Host CPU pressure | 0 / 42 | 0 / 63 | Every before/after snapshot has FileNotFoundError, errno 2; counters and delta stay null |

Each missing PSI source has **210 unavailable before/after snapshots** across
both reports. No missing source has a fabricated zero total. Aggregate sums in
`review.json` explicitly distinguish available-only sums and complete sums;
all unavailable-source sums remain null. Counter resets and changed counter
sets would retain their explicit status and null delta; none occurred here.

The observed visible-cgroup `nr_throttled` and `throttled_usec` differences sum
to zero in each report. This describes only that visible mount-root counter in
the sampled intervals. It does not show that the host was uncontended, that the
qualifier had exclusive CPU access, or that a particular MAD failure had a
known cause. RUSAGE_CHILDREN records 3,717 scalar and 9,286 owned involuntary
context switches, but these are full-driver/cumulative-child observations and
are not a causal explanation for the measured variation.

The parent reported another session running native qualifications on the same
host. That is retained as externally reported context, not independently
measured process attribution. Both producers selected CPU 0 from allowed CPUs
0–8; affinity does not reserve a CPU. Wall observations include startup, warmup,
shutdown and output capture. RUSAGE_CHILDREN may include other reaped children,
and cgroup/PSI sources may include unrelated processes. Additional observation
reads can affect invocation spacing even though the native timer is unchanged.
No such observation is used to discard a sample, relax a threshold, rerun a
benchmark or promote either inconclusive result.

## Review execution and replay

The first data-review script used `execution["argv"]` for the owned report,
whose actual field is `execution["command"]`; it stopped with a KeyError before
writing the output. [development-notes.json](development-notes.json) retains the
initial script hash, exact one-field correction and failed-attempt scope. The
corrected data review completed once; [review-attempt2.log](review-attempt2.log)
retains its exit code and result. Neither attempt ran or retried a benchmark.

```sh
python evidence/composition_performance_review_20261027/review.py \
  --repository /path/to/Hepta \
  --scalar /path/to/retained/llvm_native.json \
  --owned /path/to/retained/llvm_owned.json \
  --output /new/path/review.json
```

Place each original producer log beside its report, named
`llvm_native_performance.log` and `llvm_owned_performance.log`. The repository
must contain the frozen candidate and baseline Git objects. The script reads
those immutable revisions regardless of the checkout's HEAD, writes only the
new requested output, and refuses to replace an existing output. Input absolute
paths may differ during replay; numerical results and bound input hashes must
remain unchanged. [MANIFEST.json](MANIFEST.json) hashes every retained review
file; `review.json` also binds the final reviewer source.
