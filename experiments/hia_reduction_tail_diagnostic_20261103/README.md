# Reduction tail attribution diagnostic (not qualification)

## Finding and unchanged release status

The existing wrapper-v2 archive still passes **232/276** Rust comparisons.
All 44 failures are tail-only: their median ratios are below 1.10; the largest
p99 ratio is 56.7917. This is not evidence that those failures are noise.
The original observer records CPU usage/context switches only over a complete
row, including sample printing, so it cannot attribute an individual outlier.

This experiment adds paired wall/thread-CPU observations while keeping every
sample. It does **not** repair the compiler, relax a threshold, establish Rust
parity, activate the experimental wrapper, or qualify any P0–P7 claim.
The latest integrated source checked before this work was #564 at
`5c3741da1d36e8c1f79ec728ec325b8d973c899e` (production 154/180 reported there).
These new observations execute the older archived binary bytes, **not** a
fresh build of that integrated source. No current-source performance claim is
inherited from them.

## Frozen input and execution

- Input: `experiments/hia_empty_wrapper_20261103/execution.tar.xz`, SHA-256
  `ab1481e162e3c0b6414a2fa7a0b8f43f7a83e00315748a36b6e0576beb533ddc`.
- Every one of its 10 shared libraries is hash-checked against the archived
  identity before use and after the run. The historical source is
  `1dfbfd1565d3144233edce094cde5a8519542fd8`.
- Full archived order: 2 workloads × 5 arms; all lengths, seeds and batch loads;
  **2,070 requests and 43,470 samples**, with three warmup calls per request.
- `REGISTRATION.json` was written before compilation/target execution. It
  freezes requests, driver/runner source hashes, compiler hash, archive
  identity, CPU and clock order. The imported checksum helper in
  `tools/qualify_hia_reduction_release.py` came from the base checkout
  `5c3741d` but was not separately hashed by this registration. Future
  experiments should bind that dependency too; this historical registration
  is preserved unchanged. SHA-256:
  `a707142d44f78697b229291cf979d7ea28078faf11f0ea1dcd855ac064a55d0b`.
- Existing Debian GCC 14.2.0 compiled the observer. No software was installed.
  Linux x86-64, CPU 0 affinity; this is a shared, not exclusively owned host.
- Every sample checksum agrees with the independent periodic mathematical
  oracle, including wrapping uint32 seeds. No rerun or sample exclusion.
  The registered driver/runner sources, compiler, driver and library
  identities remained unchanged.
- Campaign wall time: 17.988862579 seconds (does not include compilation,
  extraction, analysis, engineering, or the historical cost of the binaries).

## Observation and interpretation

Clock order is CPU-start → wall-start → batch → wall-end → CPU-end.
CPU time therefore includes clock-acquisition/observer work outside the wall
interval. The signed difference wall minus CPU envelope is **not** an unbiased
estimate. Under the trusted clocks, a positive difference is conservative
evidence of off-CPU time; a nonpositive value does not prove its absence.
Values are never clamped, subtracted from a release measurement, or filtered.

Each arm has 8,694 samples. Counts with signed gap greater than 10 μs are:

| Arm | Count | Largest signed gap |
| --- | ---: | ---: |
| checked HIA | 52 | 1,805,457 ns |
| reduction HIA | 31 | 115,463 ns |
| experimental empty wrapper | 35 | 202,932 ns |
| Rust release | 51 | 1,048,218 ns |
| Rust byte release | 38 | 129,356 ns |

The 10 μs display threshold is descriptive, selected during analysis, not a
preregistered statistical test or exclusion criterion. Raw signed values for
all samples are retained.

The wrapper's largest wall observation is 6,927,239 ns, with CPU envelope
6,928,957 ns (affine, n=316201, 64 calls, seed=4294967231). All its 20 longest
wall observations have nonpositive signed gaps. The other arms also show
long CPU-accounted samples. Therefore this run does **not** establish a
scheduler-only explanation or justify discarding tail failures. Differences
in compute, allocation/cache state, observer cost and scheduling remain
possible contributors. No causal decomposition of the historical 44 failures
is possible from this new campaign.

## Observer changes and limitations

This is a deliberately separate diagnostic, not the original timing harness:

1. Two CPU-clock reads add overhead and can perturb caches/scheduling. At tens
   of nanoseconds the CPU envelope can greatly exceed the wall interval.
   No overhead subtraction or CPU-based release ratio is valid.
2. Each request starts a fresh process and loads one library, unlike the
   original persistent multi-library process. Three warmup calls do not make
   allocator/loader/cache state equivalent. Results cannot be compared as a
   paired speedup with the old run.
3. Printing occurs after all samples, rather than between them. This removes
   I/O from the diagnostic sample sequence but changes the observer again.
4. Existing original libraries are used, not rebuilt with GCC. Compiler,
   libc, clocks, kernel and host remain trusted. This adds no backend proof.
5. The successful archive contains every response. The runner attempts a
   final checkpoint on failures, but an affinity-restore or final identity-read
   failure can itself prevent that checkpoint. Arbitrary failures are not
   guaranteed to leave a complete report.
6. Controls verify that a 5 ms sleeping kernel exposes a positive gap and a
   busy kernel records CPU work. They do not calibrate nanosecond accuracy or
   prove scheduler attribution of real kernels.

The useful improvement is an inspectable, checksum-bound diagnostic observer
for the previously missing per-sample information. The next useful performance
step is a **newly registered current-source** experiment with comparable
process/allocator state and an explicit observer-perturbation control, followed
by optimization of a confirmed CPU-cost cause. Clang/Rust were unavailable in
this environment, so no new production build or claimed speedup is supplied.

## Reproduce and inspect

Run from the repository root on Linux x86-64 with existing GCC:

```sh
python -m unittest tests.test_hia_reduction_tail_diagnostic tests.test_hia_reduction_tail_summary -v
python tools/diagnose_hia_reduction_tails.py --output /tmp/hepta-tail-new-run
python tools/summarize_hia_reduction_tails.py /tmp/hepta-tail-new-run
```

The eight focused tests passed, including native sleep/busy controls and
rejecting controls for identity, missing samples, checksum, raw/parsed response
inconsistency and incomplete campaigns.

`execution.tar.xz` contains the original registration, raw stdout/stderr for
all requests, parsed observations, build command/result, exact observer and
runner snapshots, compiler identity, driver, all ten libraries, summary and
test log. Its SHA-256 is:
`45d06a3e0bbf263d77a8bdead3aa43f5ad5ad9d54a77c4605c9958c902ffd1c4`.

```sh
mkdir /tmp/hepta-tail-review
sha256sum experiments/hia_reduction_tail_diagnostic_20261103/execution.tar.xz
tar -xJf experiments/hia_reduction_tail_diagnostic_20261103/execution.tar.xz -C /tmp/hepta-tail-review
python tools/summarize_hia_reduction_tails.py /tmp/hepta-tail-review/hepta-tail-diagnostic-r1 > /tmp/recomputed-summary.json
cmp /tmp/recomputed-summary.json /tmp/hepta-tail-review/hepta-tail-diagnostic-r1/SUMMARY.json
```

`authority=DENY_ALL`, `performance_qualified=false`, and
`historical_gates_changed=false` throughout. No production code or existing
gate is modified.
