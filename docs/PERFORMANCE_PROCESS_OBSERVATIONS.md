# Observing complete performance-driver processes

The scalar and owned LLVM qualifiers now retain `process_observations` beside
their original `raw_samples`. This adds diagnostic evidence for each existing
driver invocation. It does not replace the native clock, alter any sample,
select a subset, change a threshold, or add an automatic retry.

## What is measured

| Observation | Actual interval and scope |
| --- | --- |
| `clock.wall_ns` | `monotonic_ns` around the complete process capture call: startup, warmup, native timed loop, shutdown and output capture |
| Child CPU user/system | Differences of `getrusage(RUSAGE_CHILDREN)` cumulative counters, converted from timeval seconds to integer nanoseconds |
| Child context switches | Voluntary and involuntary cumulative differences over the same surrounding snapshots |
| Child page faults | Minor and major cumulative differences over the same surrounding snapshots |
| Visible cgroup `cpu.stat` | Bounded before/after raw file snapshots and differences of its cumulative integer fields, in the kernel's named units |
| CPU pressure | Visible cgroup and host before/after raw PSI text; differences of `some`/`full` cumulative `total` microseconds only |

Nanosecond display units do not imply nanosecond resolution for `getrusage`.
The cumulative snapshots surround neighbouring observation reads as well as
the capture call; they are not the native driver's timed-loop interval.
`RUSAGE_CHILDREN` may include other children reaped by the qualifier process.
The visible cgroup mount root need not be the driver's precise leaf cgroup,
and cgroup/host PSI totals can include other processes. These records do not
establish exclusive CPU access or the cause of a performance fluctuation.

The optional Linux paths are `/sys/fs/cgroup/cpu.stat`,
`/sys/fs/cgroup/cpu.pressure` and `/proc/pressure/cpu`. Reads are bounded to
16 KiB each. Unreadable or unparseable sources remain explicitly
`unavailable`, with an error identity and any successfully captured raw text.
No missing value becomes a measured zero. Counter-set changes and decreasing
cumulative counters retain both snapshots and explicit status, with no
invented delta. PSI averages remain in the raw text and are never subtracted.

## Frozen performance contract

`tools/performance_observation.py` calls each action exactly once and records
its completion in `finally`, including exceptions. It does not sleep, modify
affinity, change scheduling priority or make a decision based on telemetry.
The qualifier still invokes the unchanged driver with its original arguments
and original 42-sample scalar / 63-sample owned order.

`evaluate_samples` is unchanged and receives only the original native sample
records. The workloads, driver source, warmup, iteration counts, seven paired
groups, 5% relative-MAD quality bound and original speed limits are unchanged.
New tests compare protocol and workload hashes against the retained original
scalar and owned reports. The original inconclusive/failed records remain
unchanged and have no retroactively invented process observations.

Current report validation requires one process observation per sample in the
exact original order, the exact command and scope, nonnegative integer
counters, correctly derived differences, monotonic interval consistency and
raw kernel-counter hashes. The scalar report binds the helper's SHA-256;
the owned report includes it in its input manifest. Complete failed owned
attempts remain auditable with the existing `require_pass=False` option;
this does not turn them into performance passes.

As with other local qualification receipts, these are consistency checks.
They do not authenticate arbitrary third-party assertions of execution.
Observation reads introduce some work between driver processes; the native
driver's timed-loop code and clock remain byte-for-byte unchanged.

## Tests and execution boundary

The helper tests execute short Python subprocesses to check actual collection,
failure propagation and retained diagnostics. Other tests use explicitly
synthetic scalar records and intercept every owned performance driver call;
the latter still execute their existing native build/correctness/allocator
controls. They do not collect benchmark timings. Tests reject missing,
reordered, negative, inconsistent, false-scope and hash-modified observations.
The unchanged native performance protocols are reserved for the final frozen
candidate run; these test results are not a performance result.
