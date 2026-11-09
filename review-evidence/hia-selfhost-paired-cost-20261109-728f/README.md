# Original compiler campaign and paired analysis — 2026-11-09

The unchanged native compiler-plan runner completed all **81 calls** on clean
source commit `81eb110607ff7c51804548cf6f1fb8e7b44c63f4`, tree
`7ef60b9fad99592f2f9a6674d65159dbe171d735`, based on source
`2e2afc1ad725db85cb8cf7eba69f657cae7c4464`. The source contract checked all 252
entries before execution. New analysis code, tests and interpretation protocol
were committed before timing. Neither the runner nor the compiler/backend was
changed for this measurement.

The original runner's verification and the new independent read-only analysis
both passed. The latter read all 503 original indexed files, replayed all
scheduled pairs and checked the original child stdout, requests, receipts,
images and complete source/output buffers. The compressed original archive
was then independently read back against the same inventory. Exact archive
size and SHA-256 are in `MANIFEST.json`.

## What ran

- 42 timed compilations: three plans, two identical source workloads and seven
  rounds in the original rotated/alternating order.
- 18 source-rejection calls, six short-capacity calls, and 15 actual calls of
  the generated example image. These are controls, not additional timing
  repetitions. Four invalid plans were rejected before native dispatch.
- 19 focused tests: 12 new synthetic evidence/accounting methods and seven
  retained compiler output-effect oracle methods. This test count is separate
  from native calls; no fixture timing is reported as a measurement.

The actual measured workload is the checked-in v16 compiler compiling its own
source and the checked-in byte-hash example. The plans retain the same Core,
source bytes and foreign-buffer ABI. Every arm produced exactly the same
complete compiler and example output bytes for all seven rounds.

## Observations

The following times are measured inside the native compiler invocation, in
milliseconds. p95 is the nearest-rank empirical quantile: at seven samples it
equals the maximum, and does not estimate a population or service tail.

| Workload | Plan | Median ms | Empirical p95 ms |
| --- | --- | ---: | ---: |
| Compile compiler | canonical | 5,055.646 | 7,792.161 |
| Compile compiler | compact immediates | 3,490.628 | 6,196.259 |
| Compile compiler | compact, swapped scratch | 4,684.313 | 5,205.637 |
| Compile example | canonical | 10.220 | 17.847 |
| Compile example | compact immediates | 11.410 | 46.310 |
| Compile example | compact, swapped scratch | 10.490 | 14.390 |

Per-round paired values differ materially from ratios or differences of those
unpaired medians. All original pair values are retained in `ANALYSIS.json`.

| Workload | Candidate vs canonical | Median paired time ratio | Positive savings | Median paired saving ms | Empirical p95 ratio |
| --- | --- | ---: | ---: | ---: | ---: |
| Compile compiler | compact immediates | 0.966769 | 5 / 7 | 165.504 | 0.795191 |
| Compile compiler | compact, swapped scratch | 0.817215 | 5 / 7 | 924.094 | 0.668061 |
| Compile example | compact immediates | 1.202576 | 3 / 7 | -1.922 | 2.594834 |
| Compile example | compact, swapped scratch | 0.964275 | 4 / 7 | 0.327 | 0.806288 |

For example, dividing the compiler medians for compact immediates by canonical
suggests a much larger reduction than the median original paired ratio
0.966769. Both summaries are descriptive; neither justifies discarding the
actual pair structure or the slower example workload.

## Costs and limits

The enclosing campaign consumed **176.225814138 seconds wall**,
**41.104692001 seconds parent CPU**, and **88.681448 seconds child CPU**. Parent
and child CPU are separate counters; nested phase/driver times are not added to
the enclosing wall interval. The original final inventory serialization and
the later read-only analysis are outside that campaign interval.

Measured emission plus rederive/link/recheck cost was 4.041556 seconds for
canonical, 15.491104 seconds for compact immediates and 18.396122 seconds for
swapped scratch. The latter two therefore carry observed preparation
differences of 11.449548 and 14.354566 seconds. These are one preparation
observation per arm, not stable production-cost estimates.

Under the restricted model of repeating the same measured compiler workload
and charging only that observed preparation difference, median paired savings
give conditional point break-even counts of 70 and 16 calls. For the example,
the compact-only plan has no positive median saving, so its count is null; the
swapped plan's restricted point count is 43,944. Unknown acquisition, authorship,
provider, deployment and recovery costs are excluded from this arithmetic.
Full-lifecycle break-even remains null for every comparison.

The host was shared and execution order was deterministic. A separately
retained observation taken **during** the campaign saw load averages
12.62 / 10.11 / 6.92 and nine allowed logical CPUs. It is not a pre-execution
reservation, child-leaf measurement, or proof of what caused an individual
timing difference. No confidence interval, causal speedup or cross-version
performance conclusion follows from this run.

**P4 remains HOLD.** The new result supplies actual paired compiler costs and
observed slow samples. It supplies no independent strong compiler/application
baseline, complete lifecycle cost, or reproducible net benefit. The full byte
output checks also do not prove arbitrary compiler semantic refinement.

## P5 remains separate

No Agent model or provider was invoked in this compiler campaign. The separate
paid-information candidate remains the scoped result described in
`docs/HIA_SELFHOST_PAIRED_COST_20261109.md`: original-native integration exists
at #829's exact head, but its complete ordinary control and independent policy
tree match the NDU value. The roughly 63.2 versus 60 witness compares full
nonmyopic planning with myopic VOI, not NDU with its strongest matched control.
**P5 remains HOLD** for an independent macro task, calibrated information,
matched Agent budgets, actual downstream outcomes and complete fees.

## Reproduce the read-only analysis

Extract `original-campaign.tar.xz` to a fresh directory. Then run:

```sh
python -B tools/analyze_hia_selfhost_machine_plans.py \
  --campaign /absolute/extracted/original \
  --expected-sealed-sha256 d21626f5d06289b483f3b80c877455881639bc7748059926aa56fc846975cb10 \
  --output /absolute/new-analysis.json
```

This reads the original bytes without rerunning a native program. Local hashes
and archive readback establish consistency, not independent historical
execution or provider-billing attestation. No default release, live worker,
adoption slot or production configuration was changed.
