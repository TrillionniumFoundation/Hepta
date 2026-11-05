# Offline target-result analysis

`analyze_target.py` summarizes existing target artifacts. It does not start a
tunnel, invoke a benchmark, provision a machine, or change the frozen runner and
plan. Until actual artifacts exist, the deliverable is the program and this
description; there is no generated target result or performance claim.

## Run after downloading real evidence

Pass the directory containing `build.json` and, when execution reached the
matrix, `tunnel/target-result.json`. An uploaded artifact may contain those files
directly rather than a literal `public` directory.

```bash
python -B experiments/openvpn_hia_20261105/analyze_target.py \
  --public /absolute/path/to/downloaded-artifact \
  --output /absolute/path/to/new-analysis-directory
```

The output directory must be new and outside the input artifact. The program
reads the artifact without changing it, hashes each input receipt it reads, and
hashes all output files in `file-manifest.json`. It rejects an input with neither
a build receipt nor a matrix receipt instead of synthesizing a run. A real
build-failure artifact can still be summarized: the unavailable matrix and its
planned slots are explicitly marked missing, using the local fixed plan with
that fallback disclosed.

Exit zero means that analysis files were written. It **does not mean that the
experiment passed**. The output reports the build's `ok`, the matrix's `complete`,
and the independent verifier's `passed` separately, together with failures and
the recorded source/runtime identities. It does not rerun the verifier, which
also checks live VM binary paths unavailable after artifact download.

## Output files

| File | Contents |
| --- | --- |
| `summary.md` | Complete case inventory; directional throughput/loss/jitter summaries and paired comparisons; endpoint process CPU/RSS; continuity/rejection observations; every case failure and missing-receipt issue |
| `analysis.json` | Exact structured summaries, receipt verdicts, source/runtime identities, selected vCPUs, input hashes, planned/missing counts, and interpretation limits |
| `raw-cases.jsonl` | Every planned or unexpected case, its matrix rows, and its full available case receipt; missing receipts remain explicit |
| `raw-measurements.jsonl` | Every planned performance workload, available raw measurements, missing slots, and standalone/orphaned partial receipts; discrepant embedded and standalone versions are both retained |
| `direction-samples.csv` | Every planned direction slot, raw receiving summary, throughput, UDP loss/jitter, status, source, and unavailable-field reasons |
| `process-samples.csv` | Every planned endpoint-process slot, user/system/total process seconds and maximum sampled RSS; both directions share this one interval |
| `direction-pairs.csv` | Every aligned throughput/loss/jitter pair, numerator and denominator values, ratio, difference, undefined-ratio reason, and both-pass flag |
| `process-pairs.csv` | Every aligned endpoint process CPU/RSS pair with the same explicit values, ratios, differences and status |
| `payload-probes.csv` | Every declared behavior/authentication probe phase, missing payload/echo counts and complete missing-sequence ranges, duplicate/invalid counts, send errors and process exits |
| `loss-and-error-fields.jsonl` | Exact nested loss, order, duplicate, invalid, missing, and error fields with source paths; overlapping observations are not summed |
| `file-manifest.json` | SHA-256 of each generated output file |

The fixed plan contains 65 cases. Its performance portion has 54 cases, four
workloads per case, and two directions: 432 direction slots and 432 endpoint
process slots. Each arm has 18 slots per workload/direction or workload/process
role. These are **planned counts**, not claims that a target run completed them.
The analyzer emits missing slots so incomplete execution cannot appear as a
smaller successful sample set.

## Comparison rules

Three pairings are retained: HIA userspace / C userspace, C DCO / C userspace, and
HIA userspace / C DCO. Each pair matches the same round, order, and workload.
Direction is added for receiving throughput, loss and jitter; endpoint role is
added for process CPU and RSS. Arm positions within each scheduled order differ,
so these are sequential matched observations, not simultaneous measurements.

Each throughput direction uses its own receiving endpoint's summary. The
client's receiving direction is `end.sum_received_bidir_reverse`; the server's
is `end.sum_received`. The recorded `sender: false`, JSON path and receiving role
must agree before its numeric values enter the normalized data. Sender-side
copies do not substitute for missing receiver observations.

All finite, identified partial observations remain included in descriptive
statistics even when the workload or case failed. Every group therefore reports
planned slots, available observations and reported-passing slots. A failed or
incomplete experiment remains failed/incomplete; its partial medians are not
presented as accepted performance results. There is no filtering of slow cases,
startup, failed intervals or losses, and there is no best-run selection.

Paired summaries take the median of individual pair ratios. They do not divide
unpaired medians. A ratio with a missing, nonfinite or zero denominator stays
undefined with a reason. Zero measured loss remains zero. UDP loss comparisons
also report percentage-point differences; jitter differences are milliseconds.
Every individual pair remains in the CSV, including regressions and undefined
ratios.

CPU observations describe the whole bidirectional interval, so the analyzer does
not divide or allocate them to traffic directions. The server always uses C DCO
in performance cases; its CPU/RSS observations remain grouped by the corresponding
client arm. Maximum sampled RSS is labelled as sampled, not as a guaranteed
process peak.

## Scope

The experiment uses one shared hosted VM, a selected vCPU set, and two local
namespace/veth endpoints. Traffic generators share each endpoint's vCPU with
OpenVPN. Whole-vCPU counters include kernel work, softirqs, generators and other
activity, and are retained in the raw measurement receipts. They are not
exclusive OpenVPN attribution.

OpenVPN process user/system seconds exclude kernel DCO work. A reduction in the
DCO process's CPU seconds is not a measurement of total DCO or whole-machine CPU
cost. The analysis makes no production, WAN, hardware-NIC, physical-host or
cross-host performance claim.

## Parser validation before real artifacts

Only tiny in-memory, explicitly synthetic parser checks were performed while
waiting for the target job. They checked the planned inventory, missing versus
zero values, retention of failed finite observations, receiver direction,
round/order pairing despite reordered input, and undefined zero-denominator
ratios. A tiny, explicitly synthetic failed-build receipt also exercised the
missing-matrix path and Markdown/JSON rendering in memory; every performance
value remained unavailable. Its temporary input was removed and no analysis
report was written. No target report was generated from these examples. They
are software parser checks, not runtime or performance evidence.
