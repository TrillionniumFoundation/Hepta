# Guarded entry outlining: prospective six-arm observation

The new opt-in `guarded-outline-v1` native layout completed its frozen campaign,
but **did not pass every strong-Rust performance gate**. It remains an opt-in
experiment; this record does not authorize default performance adoption.

## Exact source and execution

Source: `8ce43b8d8f4bf415387ebf4c52435939cd4ad6d2` on baseline
`f2b76f5741c83822be2e12cf5a50b50a8d27b96a`. The worktree was clean before and
after; all 198 bound source files and all compiler/driver/library identities
were unchanged. This evidence applies to that source, not to a subsequent
integrated commit without its own measurement.

Protocol file SHA256:
`66d45590cfcd6e7e0a09f31ea91e93d8b04af32eaf974ed2da563648e1ddb31b`.
Canonical protocol JSON SHA256:
`8706e62e4069669a0a8155c7d6b93e9701f23e4836ffa93c9bf14630ffa9ddfa`.
Result file SHA256:
`598821ccec6593e049f6f8b72f161d16acabbb02252ad8587e39d6bceed51930`.
Controller job: `1a1a490f61b-fc05-1124`, exit 0, complete durable streams,
no timeout/retry. `qualification_valid=true` denotes a complete unchanged-source
measurement, **not** successful performance qualification.

Started 2026-11-04 03:18:50.281440 UTC. Whole recorded lifecycle: 153.343 s;
actual builds and proofs: 69.862 s; correctness/refusal: 1.152 s;
registered timing: 70.181 s. CPU 0 was selected from inherited CPUs 0--47.
The Linux x86_64 host remained shared. One-minute load averages were
25.146 before and 27.005 after. No samples were removed for host load.
Actual tools: Ubuntu Clang 20.1.2 and Rust 1.95.0, generic x86_64,
Rust O3/fat LTO/one codegen unit; no PGO. Exact binary hashes and version
outputs are in the raw result and build records.

## Completeness and gate verdict

All 3,348 requests, 70,308 batches and 1,898,316 timed kernel invocations
are present. All 216 result/allocation checks and 84 machine-boundary
refusal checks passed. The original thresholds are unchanged:
median ratio <= 1.10, p95 <= 1.20 and p99 <= 1.20 against each Rust arm.

| Registered group | Rust comparisons passed | Total |
| --- | ---: | ---: |
| Historical regression | 65 | 84 |
| Historical holdout | 83 | 96 |
| Previous wrapper lengths | 66 | 96 |
| Further prospective lengths | 89 | 96 |
| **Total** | **303** | **372** |

All 69 failed comparisons remain in `OBSERVATIONS.json` and the full result.
Fifteen exceed the median limit, 26 exceed p95 and 52 exceed p99; these
categories overlap. At loads 1/16/64, 108/99/96 of 124 gates passed.
A geometric mean cannot replace these individual gates.

The equal-cohort geometric mean of observed warm median ratios was
0.97755 versus the previous empty wrapper, 0.98448 versus canonical verified
reduction, 0.92318 versus explicit-byte Rust and 0.64296 versus conventional
Rust. These are descriptive observations from two arithmetic workloads on one
shared host, without a population-wide or repeated-run claim. Empty-input
medians were worse than the previous wrapper in aggregate (ratio 1.08572).
The worst observed median Rust comparison was linear length 29, load 64:
1.47860 versus byte Rust. Its negative result remains visible.

## Resource and cost accounting

All six arms had the same observed peak allocation demand: 340,157 requested
bytes and 340,168 usable bytes. The outlined shared library occupied 20,488
file bytes per workload, compared with 20,416 for canonical reduction and
20,456 for the previous wrapper. Compile-only objects grew by 400 bytes
(linear) and 568 bytes (affine). Object and shared-file byte counts differ
because of linking/alignment and metadata; neither is a runtime heap measure.

The observer recorded library mappings/residency (24,576 bytes for all arms),
process maximum RSS (108,228 KiB for all arms), load latency, actual first
calls, allocation counters and every timed sample. Process high-water RSS
includes the launch/measurement context and is not a per-kernel allocation
bound. Rust shared files are about 1.48 MB on disk; that disk size does not
imply that the whole file is mapped or resident.

Observed outline frontend/proof/compile/link wall times were 2.474 s linear
and 1.285 s affine. Byte Rust builds took 8.502 s and 6.853 s. The frozen
warm-median amortization model favored the outline over the best measured
Rust total at horizons 1, 1,000 and 1,000,000 across all 186 cohorts. This is
an arithmetic result for the recorded build order, compiler caches and shared
host, not a balanced cold-build experiment or proof of full lifecycle benefit.
Human engineering, historical tool acquisition and energy remain unknown.
`full_lifecycle_net_benefit_established` remains false.

## Correctness and environment failures retained

The new layout preserves the original Core. It outlines only complete,
disjoint successors of an effect-free unsigned entry guard, transports every
argument unchanged and inherits the original whole-function initialization
policy. The zero edge still executes the real body; a real checked division
by zero test must abort. Z3 checks the scalar guard/substitution identities.
No machine-checked LLVM/backend refinement claim is made.

- Initial targeted 18-test run: passed (13.849 s), job
  `1a1a486855f-fc05-10c6`.
- Expanded 44-test run: 2 environment errors and 14 skips because historical
  tests selected unavailable/wrong default Clang; its complete output remains
  in job `1a1a48c35b1-fc05-10fc`. This failure was not deleted.
- Explicit actual Clang 20 run: **38 tests passed, zero skips** (36.648 s),
  job `1a1a48f5fd0-fc05-1116`. It includes native branch/trap, allocator,
  refusal, AArch64 object-ABI, original native backend and reduction checks.

## Evidence retention and reproduction

`RAW_MANIFEST.json` binds every original file by relative path, bytes and
SHA256. `ARCHIVE.json` identifies the complete raw archive on desktop.
`OBSERVATIONS.json` retains every failed Rust gate and the derived comparison,
resource and cost tables. Binaries/build products remain in the raw archive;
this repository change carries source, observations and manifests only.

Reproduce with the exact frozen source and protocol using the command in
`docs/HIA_GUARDED_ENTRY_OUTLINING.md`, a new output directory and the recorded
toolchains. A later run is new evidence; it must retain this campaign and its
failures and must not be selected as a best-of replacement.
