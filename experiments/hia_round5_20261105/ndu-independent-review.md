# Independent review of the actual HIA NDU preparation bound

**Integration recommendation: accept the narrow finite-model gate change. NDU independent value remains unproved.**

Measured source: `66d796e8abefe87d97b4096912136cdcd3299bfc`; tree `12f2cf8a830cba58ec40b50e13ee6a83bc2c49e2`; parent `996e2626d9aa89bc0e2b1017ebb858c6666604e7`. The checkout is clean. This review checked all 206 recorded active source paths plus the changed test/document and independent oracle against canonical Git blobs; it does not replace the runtime identity evidence or the forthcoming unified candidate qualification.

## Bound and implementation

For one valid artifact segment, let S be the sum of positive baseline-minus-execution-minus-holding savings and P be preparation plus proof. An initially resident and valid artifact can recover at most S; otherwise it can recover at most max(0, S-P). Invalidation ends the initial-residency credit. Giving free retirement, omitting negative intervals, ignoring shared quota competition, and adding overlapping artifact savings only overestimates recoverable benefit. Excluding an artifact larger than the entire quota is safe. Subtracting these credits from baseline cost is therefore optimistic. Taking its maximum with the previous free-execution bound preserves the lower-bound direction.

The unchanged gate/call/startup/close costs then rule out only invocations that cannot beat a feasible incumbent or fit the declared finite budget. Exact integer types, nonnegative costs, initial residency and authority boundaries remain enforced. This is a source-level argument plus finite implementation evidence, not a machine-checked general theorem or a physical deadline guarantee.

The 39 registered tests passed (10 new methods, a fixed 256-model oracle set with exact budget boundaries); raw unittest elapsed time is 2.652 s and the enclosing test command is 2.872138577 s. This review did not rerun the tests or any performance cohort.

## Retained native cohort

The unchanged four arms, three scenarios and three repetitions completed all 36 episodes / 144 steps / 147,456 timed driver calls. Allocation accounting reports 144 allocations and 144 frees, no live allocation or accounting error. All nine attempted native decisions completed and match the independently enumerated exact finite-model minimum; this review replayed their retained models without invoking native NDU.

| Scenario | Fixed median (ms) | Exact DP (ms) | Lightweight (ms) | Native NDU (ms) | NDU / best control |
| --- | ---: | ---: | ---: | ---: | ---: |
| tiny | 39.225070 | 45.512588 | 45.284623 | 45.844671 | 1.168759 |
| amortized | 144.910152 | 153.572990 | 156.029801 | 166.402148 | 1.148313 |
| invalidate-recover | 128.561955 | 130.060242 | 119.014861 | 147.461054 | 1.239014 |

**Native NDU wins 0 of 3 scenarios.** Across the 108 retained dynamic gate decisions, 36 lower bounds tighten and zero gate modes change under replay of retained full models or the explicitly recorded receipt inference. This establishes no observed old-versus-new execution saving. The dedicated nonamortizing test does establish a real no-search/no-native path for its fixed input.

## Cost boundaries and provenance

Cumulative service times are fixed 0.928389624 s, exact DP 0.999299339 s, lightweight 0.961436691 s and native NDU 1.079345183 s. The actual campaign child outer wall time is 16.257438005 s, including imports and report output. Recorded disjoint unit, pre-registration, campaign and original post-analysis phases sum to 19.689411569 s; this partial ledger excludes unmeasured work and this independent review.

The bridge was reused and its binary/manifest identities were revalidated. Its earlier measured 39.791607321 s build is charged only in the hypothetical standalone native allocation; it is not a new build or additional actual wall time in this cohort. The mutually exclusive hypothetical per-arm totals must not be summed. Human work, acquisition outside the measurement, energy, long-term storage and maintenance remain unknown; complete lifecycle cost is false.

The runtime job `1a1adf15eed-fc05-5bef` is authoritatively succeeded, exit 0, output complete, output durable, and terminal publication confirmed. Source/tool/bridge snapshots and the complete raw file manifest are bound in `INDEPENDENT_REVIEW.json`; the fetched terminal receipt is preserved in `NATIVE_RUNTIME_TERMINAL_REVIEW.json`.

## Remaining limits

The host was shared and nonexclusive; CPU 0-3 SMT siblings 24-27 were not isolated. Three repetitions cannot establish a statistical or application-wide advantage. The current controller computes exact DP witnesses before native evaluation of the same scalar objective, so native NDU cannot improve that model optimum. The benefit claim still requires measured end-to-end improvement against strong fixed, lightweight and exact DP controls under a suitable real workload. No such improvement is established here.

Include `tests.test_hia_ndu_preparation_bound` and its source identity in the unified candidate registration. The new unified run must bind this change together with Safe Core, AOT, verifier, toolchain and artifacts. Authority remains `DENY_ALL`; this review grants no safety certificate.
