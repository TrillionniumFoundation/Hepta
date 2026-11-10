# Thin empty-entry wrapper: measured benefit and remaining regressions

The empty path now compiles to `test / jne / xor / ret`, before any
callee-saved register saves. It reaches the same freshly verified Core body:
the zero branch substitutes literal zero only after checking the actual
`usize` argument; every other argument is unchanged. LLVM inlines that call.
The generic branch calls the complete body with unchanged arguments and a
`noinline` hint. The experiment never manually replaces the resource body with
a constant return. Production native admission still refuses this modified IR;
the experimental builder does not grant deployment authority.

This fixes the large **median** empty-path overhead in these two workloads. It
does **not** pass every frozen gate, and it has nonempty regressions. The
candidate therefore remains experimental and is not enabled by default.

## Frozen protocol and complete result

Source `1dfbfd1565d3144233edce094cde5a8519542fd8` ran `wrapper-v2` on the shared
Linux x86-64 main host with the same driver, default affinity rule, compiler
settings, 21 samples per request and loads 1/16/64. The original v2 lengths,
seeds, both Rust arms and median/p95/p99 thresholds remain intact. Eight new
lengths and three new seeds were registered before compilation and timing.

All **2,070 requests / 43,470 timing samples**, compiler outputs, proof queries,
LLVM, assembly, libraries and raw driver streams are retained in the complete
archive. All 180 correctness and 70 boundary-refusal observations pass. Source,
tools and executed artifact identities agree before and after the run. Total
campaign time was 63.813 s: build/proofs 38.387 s, timing 24.312 s and the
correctness/refusal phase 0.465 s. These nested times must not be added again to
the outer total.

| Candidate comparison group | Passed | Total |
| --- | ---: | ---: |
| Historical regression lengths vs both Rust arms | 66 | 84 |
| Historical holdout lengths vs both Rust arms | 81 | 96 |
| New prospective lengths vs both Rust arms | 85 | 96 |
| All Rust comparisons | **232** | **276** |

The unchanged four-arm historical replay passed 145/180 in this same run. The
earlier clone-only observation remains separately preserved with its own
219/276 result; its different prospective lengths prevent treating those two
totals as a paired improvement estimate.

## Empty path and nonempty tradeoff

| Empty workload, 64 calls | Original reduction median | Thin wrapper median | Rust release / byte median |
| --- | ---: | ---: | ---: |
| Linear | 238 ns | 163 ns | 163 / 163 ns |
| Affine | 261 ns | 164 ns | 164 / 163 ns |

The empty-path batch median improves 31.5% and 37.2% against the original HIA
reduction in the same run. All twelve empty-path **median** gates pass. Two
single-call tail comparisons still fail: linear versus Rust byte at p95, and
affine versus Rust release at p95/p99. The complete empty-path result is
10/12, not 12/12.

Across 132 nonempty cohorts, the geometric mean of the candidate/original-HIA
median ratio is 1.007166, a 0.72% slowdown. This descriptive aggregate does not
replace any cohort gate. Complete gates pass for 97/132; four median ratios
exceed 1.10:

| Workload | Length | Calls per batch | Candidate/original-HIA median |
| --- | ---: | ---: | ---: |
| Linear | 4096 | 1 | 1.146780 |
| Linear | 269 | 1 | 1.137097 |
| Affine | 97 | 1 | 1.101266 |
| Affine | 97 | 16 | 1.138855 |

These are retained failures. Shared-host scheduling and layout can affect this
measurement, but they are not grounds to discard a sample or relabel a failure.
The experiment establishes neither complete Rust parity nor overall dominance
over the existing HIA reduction.

## Custody and reproduction

`execution.tar.xz` is 1,071,960 bytes, SHA-256
`ab1481e162e3c0b6414a2fa7a0b8f43f7a83e00315748a36b6e0576beb533ddc`.
`SUMMARY.json` binds the uncompressed full result and preserves the complete
nonempty failures and empty cohorts. The full 552-comparison assessment was
independently reproduced from the archived raw measurement rows using the
current typed registration/cohort checker.

`source-1dfbfd1.bundle` preserves the four measured-source commits above
`18291446e048f760f5519823e865727ef51db11a`. `MANIFEST.json` binds the archive,
summary and source bundle. Re-run from the exact source with:

> Removed source/mixed-campaign reproduction command; its harness is not
> delivered. No historical result is promoted to current qualification.

The original Core candidate still adds three evaluator steps, so evaluator
quota-stop behavior is excluded. Native compiler/linker/libc/hardware remain
trusted; backend refinement and whole-language soundness are unproved. Human
engineering, historical acquisition and energy are unknown. No full lifecycle
net benefit is claimed.
