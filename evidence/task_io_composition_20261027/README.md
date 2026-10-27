# Task-tree / local I/O composition observations, 2026-10-27

This archive retains **all four qualification attempts**, including the first
failure, without rewriting their JSON, commands, raw streams or results. It is
evidence for the indicated source snapshots, not a qualification of a later
integrated candidate or all production blockers.

## Source snapshots and observations

The implementation is commit
`a064354a769797d2e4cc219a211d0b2ab521e9f5`. Commit
`9bab0ea41b5eb307bf7cc83d5ee043213fe8ee45` adds a blocked-child adoption-refusal
and pool-reuse control, its exact denominator and corresponding documentation;
it does not change runtime implementation. Both have compiler SHA-256
`80c75b69e289a489593792994606c7347cb0b679280495e57ab95bde19ec6636`.
The qualifier and fixture input hashes differ between these commits. The
archive manifest verifies every recorded `source_files` hash against the
stated Git snapshot before assigning that snapshot to either frozen run.

| Directory | Source snapshot | Repetitions | Actual outcome |
| --- | --- | ---: | --- |
| `dev-001` | Uncommitted development state | 1 | Failed: `unexpected successful-process stderr`. Native control builds emitted naming warnings; the final strict validator refused the evidence. |
| `dev-002` | Uncommitted development state | 1 | Passed at that state after the test harness explicitly allowed generated type names. This predates the final cross-group admission-race fixture. |
| `a064354-three-rounds` | `a064354` | 3 | Passed. Includes all four races, with 612 registered buffer allocations and 612 actual releases, zero remaining live buffers. |
| `9bab0ea-three-rounds` | `9bab0ea` | 3 | Passed. Adds refused adoption of a child already in the native poll path, synchronous cancel/join cleanup, then a new group's timeout/retry on the same pool. |

The final unmodified report is
[`9bab0ea-three-rounds/report.json`](9bab0ea-three-rounds/report.json), SHA-256
`def42f91932086ffdce23340dc963e6af0738a3521e6f210c9f2872821a9ca14`.
Its fixed denominator is:

- Nine case plans: three checked source programs, one native control matrix,
  four separately compiled incorrect runtimes and one illegal mutable-alias
  compile control.
- Three repetitions of the eight executable cases: **24 actual executions**,
  comprising 12 expected successes and 12 expected incorrect-runtime failures
  or timeouts. The alias control is actually compiled and rejected with
  `E0499`; it is never reported as an execution.
- Ten freshly checked invalid source controls, with their required diagnostic
  codes retained in the receipt.
- **672 race trials**: 192 parent/child cancellation-failure races, 192
  attachment-cancellation races, 192 readiness-cancellation races and 96
  cross-group byte-admission races.
- Three refused-adoption cleanup/reuse controls. Each first cancels and joins
  an already waiting child, checks all I/O reservations are zero, then admits
  a new group in the same explicit pool and completes timeout/retry cleanup.
- **621 registered-buffer allocations and 621 actual allocator releases**;
  each repetition observes 207/207, live buffers zero and 137 actual calls
  into the native poll boundary. These count the explicitly registered
  fixture buffers, not every allocation of the runtime or process.

Every repetition also exercises partial-read preservation, native reactor
drop, completion-before-cancellation, all four I/O budget dimensions,
fallible registry/poll metadata allocation, wake-socket setup refusal,
registration-limit recovery, timeout and native poll-error recovery. The four
incorrect runtimes remove the wakeup, byte admission check, reservation
release or actual buffer release, respectively. Their distinct observed
failures are retained. Elapsed process times support timeout checking only;
**this is not performance evidence**.

## Regression logs

[`affected-115-tests.log`](affected-115-tests.log) records the six affected
test modules on the implementation snapshot: **115 tests passed, zero skips**,
47.338 seconds. [`adoption-11-tests.log`](adoption-11-tests.log) records the
focused module after the final fixture addition: **11 tests passed, zero
skips**, 12.493 seconds. These include actual native fault/race controls,
strict evidence mutation checks, source/emitted-code replay, binary/object
byte checks, and partial non-UTF-8 timeout stream retention.

An earlier manual source smoke run in the default sandbox failed an I/O
pipeline assertion. Its generated temporary directory was not retained and
its cause was not established. It is not represented as a successful run or
invented JSON receipt here. The retained native qualifications were executed
with local Unix-socket execution permitted; they use the same production
runtime source. This archive's first structured qualification is `dev-001`
and remains failed.

## Reproduction and retention

The frozen final run used:

```sh
python -m tools.qualify_task_io \
  --output /tmp/hepta-task-io-qualification-final-v2-20261027.json \
  --rustc /tmp/hepta-ai-rust-1.90.0/bin/rustc --repeats 3
```

Use a **new output path** for a new run; the qualifier refuses to replace an
existing attempt. The full adjacent `.files` directory remains at each
original path recorded in `manifest.json`. For Git, the archive retains raw
JSON, generated Rust/C source and raw stdout/stderr bytes. Native executables
and object files remain local and are deliberately not committed; their
original paths, byte counts and SHA-256 values are retained in the manifest
and report. The manifest also binds every archived file to its original
bytes. Raw process stream filenames ending in `.bin` contain captured stream
bytes, not executable binaries.

`tools.qualify_task_io.validate_report(report, minimum_repeats=3)` performs
data and current-source validation only. It needs the original retained
artifacts, including native executables, and the matching source/tool bytes.
The Git text archive alone is not sufficient to call it successfully on a
machine without those artifacts. A new integrated candidate must generate a
new receipt; a historical receipt is not converted into current evidence by
editing hashes or relocating recorded paths.

## Qualified boundary

The implementation joins a worker-owned, caller-driven local reactor to its
existing explicit task pool. It shares accounting for reactor/endpoint/
request reservations and admitted buffer capacities, propagates tree
cancellation through an owned socket peer close, and keeps reactor access on
one thread. No extra background executor or cross-thread reactor access is
introduced. Read the protocol and lock/lifetime rationale in
[`docs/TASK_TREE_IO_COMPOSITION.md`](../../docs/TASK_TREE_IO_COMPOSITION.md).

This closes the tested composition gap for that profile. It does **not**
qualify async/await, TCP/TLS, arbitrary file I/O, long-running service loads,
whole-process allocation or actual stack/RSS limits, arbitrary worker/FFI
termination, fatal `Arc` allocation failure recovery, independent I/O IR
refinement, or C/LLVM lowering of this new combined protocol. Runtime races
are finite observations, not a universal deadlock or soundness proof. The
receipt detects inconsistent or stale evidence; it cannot authenticate an
arbitrary third party who can rewrite all files and claimed observations.
