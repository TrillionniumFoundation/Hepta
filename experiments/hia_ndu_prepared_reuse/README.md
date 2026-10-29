# Bounded prepared-artifact reuse and actual NDU cost evidence

The prepared-artifact boundary now supports reuse of an internally proved,
self-built, sealed checksum image with bounded leases and explicit release
debt. The actual experiment validates this mechanism. **NDU's net-benefit and
two-profitable-opportunity gates remain false.** The earlier fresh-proof
activation experiment and its negative costs remain unchanged.

## Source and verification

| Item | Exact recorded identity or result |
|---|---|
| Reviewed runtime source | `3c547848a4e9e488b42de631bb29ba039c489093` |
| Experiment source, committed before observations | `b53d61cd3cdb522ccd718f3fdc7cd62d1d5964a2` |
| Independent runtime review | `34984e4a96071450d1331a6573e6fb6bd56a4c95` |
| Runtime/native regressions | 24 passed, 0 skipped, actual compiler/proof/child execution |
| Protocol/attribution regressions | 4 passed, 0 skipped |
| Functional smoke | 12 policy episodes and 4 post-run controls admitted; economic qualification disabled |
| Formal policy episodes | 24/24 admitted; 618 actual workload outputs correct |
| Calibration and mechanism controls | 54 calibration outputs and 8 paired mechanism outputs correct |
| Post-run opportunity controls | 4/4 admitted; 100 actual outputs correct |
| Total actual native workload batches | 780; each batch calls the workload 131,071 times |
| Source, compiler/Python and driver rechecks | Unchanged |
| Policy artifact admissions | 43 actual proof/build admissions for 618 deliveries |
| Policy ownership cleanup | All complete; no retained release debt |

The 24-test native regression belongs to the reviewed runtime commit. Those
runtime files are unchanged in the measured experiment commit. The independent
review verifies the producer's source and log; it does not claim a second
independent test execution. Development failures, including the corrected
fault-injection interception error, are retained and remain unqualified.

Full source hashes, commands, tool identities, proof/build receipts, actual
driver output, request/response frames and stage costs are retained. The raw
run directory was `/tmp/hepta-next-ndu-prepared-formal-01`. A source bundle
preserves the measured local commit with public `2f49151` as its prerequisite;
later integration commits must preserve the original result attribution.

## Runtime boundary

The implementation and its limits are described in
[`HIA_PREPARED_ARTIFACT_LEASES_20261029.md`](../../docs/HIA_PREPARED_ARTIFACT_LEASES_20261029.md).
It extends the existing private prepared-proof mechanism and runs the checksum
workload in a fresh child process. It does not import foreign DSOs or serialized
proof authority. Fixed, complete finite DP and NDU receive exactly the same
reuse eligibility and limits.

Admission still independently proves and builds each artifact. Every lease and
run rechecks the source/tool/policy binding, canonical Core, proof ancestor,
sealed executable bytes and descriptor identity. The actual driver verifies
its loaded ELF mapping. A candidate retains its baseline ancestor, and active
leases prevent retirement. Unknown close outcomes remain charged and never
retry a possibly reused descriptor number.

Review found and closed three concrete defects before measurement: interrupted
publication could close a still-visible entry; driver metadata failure could
lose an acquired descriptor; compiler identity used an unbounded blocking read.
The final tests exercise those exact paths, independent read/memfd release
debts, cancellation, stale receipts, policy drift and concurrent run/close.

The configured cap is eight entries, 32 MiB of retained encoded metadata and
sealed image bytes, four outstanding leases and 256 execution attempts per
session. This does not bound Python object overhead, child heap, disk or process
RSS. Preparation deadlines are cooperative checks around bounded stages, not
a hard real-time guarantee. Python, the checker, compiler, driver and OS remain
trusted. Whole-language soundness and Core-to-machine-code correctness are not
established by these tests.

## Shared proof-reuse mechanism

For each module, two interleaved pairs executed the same admitted guard-wide
image at `n=4093`, with identical inputs and the same lease/identity checks.
The fresh-equivalence arm additionally solved the exact theorem under the same
explicit proof policy. Both arms executed and checked their native outputs.

| Module | Fresh-equivalence median | Prepared-equivalence median | Actual paired savings |
|---|---:|---:|---:|
| `byte_sum` | 1.128352 s | 0.289630 s | 0.803266 s; 0.874179 s |
| `packet_xor` | 1.385520 s | 0.539057 s | 0.739861 s; 0.953066 s |

This is a benefit of the shared runtime mechanism. It does not establish an NDU
algorithm advantage. These four pairs are finite observations, without a
statistical superiority claim. They also do not measure a direct before/after
speedup against the older experiment, whose guard, workloads and policy timing
profile differ.

## Policy comparison and actual opportunity tests

The protocol contains short-lived, stable, changing and shared-budget traces.
The two semantic modules have different Core hashes. `guard-small` admits
inputs through 128; `guard-wide` through 4096. Input 32749 exercises the
preserved fallback. Each episode has one consumable candidate-build credit,
shared across its modules. A failed attempt would still spend that credit.

Each policy starts with the same interleaved calibration bank and registered
input trace. It subsequently sees its own completed observations. Fixed commits
the strongest calibrated stationary suffix assignment after the common initial
probe. DP solves the complete finite multiple-choice allocation under the same
information and budget. NDU evaluates exactly those assignments through the
unchanged pinned native framework. This finite model is not an optimal-control
proof over every possible future observation tree.

NDU made **6 actual candidate builds** and produced **91 correct candidate
outputs**. Of those, 47 input batches satisfy their declared fast guard; these
are input-condition observations, not hardware branch-counter measurements.
All **148/148 NDU choices match complete DP** when audited on the exact model
submitted to NDU, with zero modeled selection regret. There were **zero**
modeled decisions in which two individually profitable modules competed for the
one remaining credit.

Before holdout execution, the registered rule selected one nonbaseline target
per module for independent opportunity controls. After all policy episodes,
fresh baseline and candidate sessions executed the complete shared-profile
trace, including their own preparation and cleanup. No resulting timing fed a
policy decision.

| Module and chosen target | Baseline total | Candidate total | Observed baseline minus candidate |
|---|---:|---:|---:|
| `byte_sum`, `guard-small` | 10.123576 s | 11.025979 s | **−0.902403 s** |
| `packet_xor`, `guard-wide` | 17.727770 s | 20.597866 s | **−2.870096 s** |

Both opportunity controls are negative. The group-0 initial shared-budget model
predicted `byte_sum` would lose 0.564535 s and `packet_xor` would save 0.355313 s.
NDU and exact DP selected `[base, guard-wide]`; that selected candidate was
actually built and correctly executed. This is one forecast-positive option,
not two competing profitable opportunities. Both the observed-two-opportunities
gate and its exact NDU competition-attribution gate remain false.

## Complete registered warm costs

Seconds below include each arm's current preparation, calibration, own artifact
proof/build, runtime checks, native execution, evidence work and shutdown. The
92.294971 s common preparation is charged once per standalone arm. Each
per-profile row is a separate standalone interpretation; **do not sum the
profile rows** to obtain the combined total.

| Profile | Strong fixed | Complete finite DP | NDU warm | NDU below both controls |
|---|---:|---:|---:|---|
| Short-lived | 94.409979 | 94.635670 | 94.646108 | False |
| Stable reuse | 113.706522 | 120.959308 | 113.865344 | False |
| Changing load | 120.895474 | 123.613513 | 152.015742 | False |
| Shared budget | 156.004543 | 150.171747 | 154.680012 | False |
| Combined, common preparation once | **208.131606** | **212.495324** | **237.767684** | **False** |

The full registered driver observed 533.293239 s before final aggregate
encoding, including 59.476824 s of post-run opportunity controls. Those controls
are validation work and are reported separately from strategy deployment
totals. Toolchain installation, dependency-cache acquisition, outer Python
startup/imports/argument parsing, final aggregate encoding/archive and human
engineering are outside the registered strategy-cost scope.

No new cold controller build was measured. The previous 32.133198039 s
empty-target native build remains an explicitly historical reference for the
unchanged controller/tool/wrapper. Adding that reference yields 269.900882 s
for NDU's combined warm-plus-historical cost. It is not a new cold measurement,
and `new_cold_net_benefit_qualified` remains false.

## Limits that remain open

The inherited rotate/reverse order with two groups is not fully counterbalanced
within each profile. The exact orders are retained in `SUMMARY.json`. This was
noticed during the frozen run; no source, order, sample or acceptance rule was
changed. The host is nonexclusive and is not a verified physical dot
workstation. Known team model/native workloads were paused for the measured
interval, but other host/runtime variation is not isolated.

For example, NDU's second changing-load episode cost 41.255218 s, including
37.494349 s in delivery stages, 1.272234 s in candidate preparation and
1.450840 s in controller stages. Some native and parent CPU measurements also
rose substantially. These records do not justify attributing the whole gap to
NDU's algorithm, compilation, or any particular external cause. No observations
were discarded.

The remaining economic blockers are concrete: this trace did not demonstrate
two profitable amortized opportunities; NDU did not beat both strong controls;
and prediction uncertainty/order/host effects remain insufficiently separated.
The bounded reuse, identity, attribution and release checks are implemented and
tested. No gate was relabeled to convert the negative result into a benefit.

`authority = DENY_ALL`, `safety_certificate = false`,
`statistical_superiority_established = false` and prior negative evidence remain
unchanged. These two kernels do not establish an application-wide advantage
over Rust, C or C++.

## Inspect retained evidence

[`SUMMARY.json`](results_20261029/SUMMARY.json) contains the compact totals and
gate inventory. [`INDEX.json`](results_20261029/INDEX.json) indexes lossless JSON
fragments for the full result, calibration bank and raw-file inventory. The
full raw outputs remain separately archived, including native artifacts and
all failed development logs.

```sh
python experiments/hia_ndu_prepared_reuse/results_20261029/inspect_evidence.py
```

This verifies three reconstructed datasets and executes zero experiments. A
fresh run requires the registered toolchain, exact native controller identity,
an explicitly historical build envelope, a clean committed checkout and a new
external output directory. It must retain its own source identity and results.
