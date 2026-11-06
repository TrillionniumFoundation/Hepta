# Independent result audit: frozen composition 0a06ef4

The frozen composition completed proof, independent replay and all composition commands under the original budgets. The strong-AOT tail/cold-call and NDU net-benefit targets remain open. This audit reads retained evidence and produces no new measurements.

## Identity and terminal evidence

The measured source is `0a06ef4f0894681af92b0caefba0704c1278d2cc`, tree `a5239982f9fd8f08ab3a6e791147fc989e8d9df6`. Main job `1a1ae149dcf-fc05-5d36` and audit job `1a1ae3f635c-fc05-5e6d` both have authoritative succeeded / exit 0 states, complete durable output and confirmed terminal publication. Source/tools were unchanged; identity_errors and independent consistency errors are empty.

All 36 commands and 34 qualification flags passed. CORE contains 613 identical planned, started and finished IDs, with zero failures, errors or skips; every S3 CORE ID remains, with 23 additions. DENY_ALL remains in force. The twelve wider production refinement obligations remain unproved.

| Stage | Outer wall, seconds |
| --- | ---: |
| Proof | 595.116502644 |
| Independent replay | 43.595967989 |
| Composition | 2005.257633654 |
| Entire sequence | 2670.960663875 |

Both proof budgets remain 600 seconds. The sequence already includes its nested stages.

## AOT results

All 3,348 requests, 70,308 batches and 1,898,316 calls were retained. The two workloads, six arms, lengths, seeds, batch sizes and original thresholds are unchanged: median ≤1.10, p95 ≤1.20 and p99 ≤1.20 against each paired Rust baseline.

| Gate | Passed / total |
| --- | ---: |
| Median | 372/372 |
| p95 | 371/372 |
| p99 | 340/372 |
| All three jointly | 340/372 |
| Cold first call | 38/48 |
| Memory | 5680/5680 |
| All resource/cost gates | 6842/6852 |

Of 32 joint failures, 31 fail p99 alone and one fails both p95 and p99; none fail p95 alone. All 10 cold failures are n=0, split linear 5 / affine 5. The dual tail failure is linear / prospective / n=101 / calls=64 / rust_release: median ratio 0.640730, p95 2.226113 and p99 8.325879. The worst p99 ratio is 47.254753 at affine / prospective / n=331 / calls=1 / rust_byte_release.

These are batch-latency observations. Each cell pools 63 samples from three seeds; its empirical p99 is the largest sample. No sample was excluded and no failure was waived as noise. This is not a population-tail guarantee.

| Resource/cost category | Passed / total |
| --- | ---: |
| cost.build_and_proof | 4/4 |
| cost.cold_first_call | 38/48 |
| cost.estimated_automated | 1116/1116 |
| cost.median_load | 4/4 |
| memory.library_file | 4/4 |
| memory.loader_backing_resident_bytes | 48/48 |
| memory.loader_mapped_bytes | 48/48 |
| memory.peak_requested | 1116/1116 |
| memory.peak_usable | 1116/1116 |
| memory.requested_total | 1116/1116 |
| memory.stack_max_distance | 1116/1116 |
| memory.usable_total | 1116/1116 |

The S3→current matched-cell transition is pass→pass 289, pass→fail 26, fail→pass 51 and fail→fail 6. The change from 315/372 to 340/372 counts passing cells; it is **not a speedup percentage**. SUMMARY.json retains every transition and all 32 joint / 10 cold failures. Two complete registered observations on a shared, nonexclusive host do not establish a controlled causal speed estimate. The allocator-hook stack distance is not a whole-function stack bound.

## NDU: 0/3 on this frozen composition

The cohort contains 36 real episodes, with three repetitions per scenario/policy; nine actual native invocations completed. Median service walls below are in milliseconds.

| Scenario | Fixed | Lightweight | Exact DP | Native NDU | Native / best control |
| --- | ---: | ---: | ---: | ---: | ---: |
| tiny | 37.740465 | 43.726289 | 38.746358 | 39.043825 | 1.034535× |
| amortized | 140.300471 | 139.742754 | 147.038824 | 153.246003 | 1.096629× |
| invalidate-recover | 121.181635 | 108.780444 | 113.964074 | 133.801081 | 1.230010× |

The fresh bridge took 37.015251921 s internally and 37.236646032 s at the outer command boundary. Its target cache was empty; the report does not claim a completely cold machine. Shared build/training/proof/calibration cost 9.965018836 s and the common runner remainder 0.431643231 s. The native arm additionally pays the bridge outer-minus-inner 0.221394111 s once.

| Policy | Registered complete outer solo-campaign allocation, seconds |
| --- | ---: |
| exact_dp | 11.309013613 |
| fixed | 11.283078238 |
| lightweight | 11.299919508 |
| native_ndu | 48.631855777 |

These are alternative allocations from one shared multi-policy campaign, **not four independently executed solo campaigns; do not sum them**. The two actual outer commands, fresh bridge build and NDU qualification, total 51.333880935 s and are already nested in composition/sequence wall. SUMMARY.json gives each scenario's three-repetition service sum. The protocol has no independently measured per-scenario build/shared-cost allocation, so per-scenario standalone full-lifecycle cost is explicitly unobserved; charging the bridge three times would double count. No cost from the separate 66d specialist study is substituted here. Historical acquisition, human work, energy and longer-term maintenance/residency remain outside complete lifecycle measurement.

## GitHub and historical-test boundaries

The final API snapshot for exact published head `67da0ab0a51203f6f640c4459bc15bef442885b8` still has 12 queued workflows. Of 106 jobs, six actually completed successfully (four Windows, two macOS AArch64), and 100 remain queued. The POSIX non-reaping step was skipped in both Windows ABI jobs; Visual Studio setup was skipped in both macOS jobs. All per-job/per-step states are retained. Complete host-profile qualification belongs to the separate artifact audits; successful step names alone are insufficient.

S3 CORE preservation does not mean every historical research test is identical. The separate 5ee6 branch has 43 methods in the shared-source test file; S3/current have 40 identical common method ASTs plus 10 new structured-source controls in another file. Historical dynamic Raw-subclass read semantics have an unretained static counterexample. HISTORICAL_TEST_SCOPE_AUDIT.json documents that scope; no frozen source was changed.

Primary evidence: FINAL_AUDIT.json, SHA256 `de6f81fb7fc74b9f17da4bf12db8e3eed561de78cfe1def9a81d5372377b270f`; TERMINAL_STATUS.json; GITHUB_FINAL_SNAPSHOT.json. Parent walls, nested child walls and alternative cost allocations are reported separately and must not be added together.
