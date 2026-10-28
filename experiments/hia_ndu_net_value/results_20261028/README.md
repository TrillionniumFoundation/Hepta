# Formal NDU complete-cost result on the unified HIA source

Measured source commit: `96bc1b4598a8469b0d44b09e7e97d4705cac2cc5`.
Native source: `c4a1bbed3a39beba43a6abf1a18b6f75c5725c21`, Rust 1.90.0.
The source and identity remained unchanged throughout this run. Later CI or
evidence commits do not replace the measured source identity.

The complete frozen protocol ran once: **36 controller episodes, 27 application
episodes, 1,152 controller queries, and 252 actual native application
observations**. All 252 loaded executions had a fresh independent proof. Every
application output and compile-credit bound was admitted. No sample was
excluded. The registered full-cost advantage gate is **false**.

## Costs by application profile

Values below are seconds across the three registered groups. Each row is an
independent standalone deployment interpretation: it includes the full common
registration and calibration once per arm, and includes the complete native
build once for NDU's cold value. **Do not add these rows to obtain the combined
workload total**; doing so would count common setup repeatedly.

| Profile | Strong fixed | Complete DP | NDU warm | NDU cold | Cold advantage gate |
| --- | ---: | ---: | ---: | ---: | --- |
| Stable reuse | 24.705403 | 23.865143 | 24.706518 | 72.317384 | false |
| Changing load | 30.879912 | 28.914087 | 27.926390 | 75.537256 | false |
| Shared compile budget | 43.472299 | 43.881308 | 42.693707 | 90.304573 | false |

The separately measured empty-target native build cost was **47.610866564 s**.
The combined-workload totals charge common setup only once: fixed **65.123898 s**,
DP **62.726822 s**, NDU warm **61.367863 s**, and NDU cold **108.978729 s**.
Warm totals exclude only that native build. Proof, compilation, native admission,
artifact checks, execution, logging and shutdown remain charged under the frozen
cost scope. Toolchain installation, acquisition of preexisting dependency source
caches and final aggregate encoding/archival remain declared exclusions.

## What the warm difference does and does not show

Only **one** candidate compilation occurred in all 27 application episodes:
group 0, shared-budget, **DP**, module 1, `guard-small`. That artifact was selected
for five subsequent module executions. The other 211 selected module targets
were `base`. **NDU compiled no optimization candidate in any application episode.**
Consequently, its small combined warm difference is not evidence that NDU found
a better optimization. It includes variation in base execution, validation and
control costs on this one nonexclusive host. No statistical superiority or
long-run break-even point is established.

The shared-budget workload uses two independent instances of the same kernel
with different declared input-size traces and per-instance artifacts. It is not
a pair of heterogeneous source modules or a general shared compilation cache.
One real compile-attempt permit is enforced; failed builds cannot refund it.
The run checks that bound, but mostly selecting `base` means it did not strongly
exercise competing profitable optimization opportunities. Six epochs are finite
reuse, not evidence about an indefinite operating lifetime.

## Controller mechanism observation

These warm totals are for the separate controller-only experiment, with common
registration included once per standalone arm:

| Controller | Warm seconds |
| --- | ---: |
| Fixed reuse | 0.772639 |
| Complete DP reuse | 0.790015 |
| Native one-shot | 2.072954 |
| Native session with full rehash | 1.835127 |
| Native session with sealed-image checks | 1.282943 |
| Sealed session with exact advisory cache | 1.570831 |

The sealed-image path reduced observed transport cost relative to repeated full
rehashing. It still cost more than the finite DP control. The advisory cache
also cost more than the uncached sealed session in this run. Cold native
controller totals additionally include 47.610866564 seconds of actual build
cost. These are mechanism measurements, not an application optimization claim.

## Evidence inventory

`SUMMARY.json` and `RESULT_TOTALS.json` contain the numerical results and exact
scope. `REGISTRATION.json`, `NATIVE_BUILD_IDENTITY.json` and
`NATIVE_BUILD_ENVELOPE.json` bind the actual source, native source, toolchain,
binary and build costs. The JSONL parts preserve every measured controller
query and episode, application episode and observation, decision model and
selection, and calibration observation. `EVIDENCE_INDEX.json` gives their hashes
and counts. Full repeated native request/response and proof payloads remain in
the hash-bound raw files identified there; this compact archive does not claim
those omitted payloads or native binaries were all committed.

The original complete result, calibration bank and 4,541-file raw manifest are
retained at the absolute paths recorded in `EVIDENCE_INDEX.json`. The registered
code can reproduce the experiment, but new runs will have different timings.

Earlier negative experiments remain unchanged. Advisory caching stays off by
default, `authority` remains `DENY_ALL`, and `safety_certificate` remains false.
