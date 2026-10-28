# Registered finite native lifecycle load

`tools/soak_hia_native_runtime.py` registers and executes a bounded, repeatable
native entry lifecycle workload. Every accepted call loads an actual sealed
Clang image in the existing restricted native child and uses the fixed native
loan diagnostic protocol. This is a proposed additional scoped qualification;
adding the producer does not establish that the hosted profile has run.

The workload exercises repeated child creation/reaping, private buffer
allocation/drop, captured version identity, activation, rollback, drain, build
publication cancellation, and partial observations on native failures. It uses
the existing `examples/hia_native_lifecycle/swap.json` fixture and exact
registered byte-swap candidate replay. No native results or successful
compilation receipts are substituted.

## Relationship to other evidence

The [native dispatcher](HIA_NATIVE_VERSION_DISPATCH_20261027.md) provides the
per-call image and cleanup owner. The [application benchmark](APPLICATION_BENCHMARKS.md)
uses a common C driver and separately compiled application implementations; its
request timing and allocation instruments have different boundaries. The
[shared task runtime](SHARED_RUNTIME.md) tests actual native tasks, attached
reservation pools and fault controls. This producer has reviewed those
measurement boundaries, but does not silently turn the scalar dispatcher
fixture into an application or shared task runtime workload.

In particular, two simultaneous isolated children are not shared-state
migration, callback handling, structured task migration or a persistent native
worker. The selected diagnostic loan and endpoint bytes are observed; other
bytes and the complete resource ledger are not observed. Diagnostic syscall
handshakes and forced zero initialization change execution costs. Their
latencies cannot qualify uninstrumented production code or an instruction
schedule.

## Fixed profiles and acceptance

The exact profiles are closed dictionaries in `PROFILES` in the producer.
Registration records their canonical SHA-256 and binds the implementation,
fixture, source snapshot, Git commit, Clang and Python executable identities.
A changed budget or workload requires a new protocol/source identity and a new
registration. Budgets and acceptance thresholds must not be changed after
examining a hosted run's outcomes.

| Field | `hosted-native-lifecycle-30m.v1` |
| --- | --- |
| Total producer wall budget | 1,800 seconds |
| Stop starting new epochs | 1,620 seconds after producer start |
| Maximum completed epochs | 512 |
| Calls in a complete epoch | 33 |
| Maximum attempted calls | 16,896 |
| Maximum simultaneous native calls | 2 |
| Minimum pair admission spacing | 0.2 seconds, with no accumulated catch-up queue |
| Ordinary diagnostic child timeout | 8 seconds |
| Deliberately withheld ACK timeout | 1 second |
| Public build wait / close wait | At most 60 seconds each, capped by remaining producer budget |
| Retained output budget | 96 MiB, including a 2 MiB accounting reserve for the report and atomic replacement |
| Free-disk stop threshold | 128 MiB |
| Drained-parent sampled RSS stop threshold | 512 MiB |
| Drained-parent FD growth stop threshold | More than 4 above the initial sampled count |
| Minimum actual observation duration | 1,500 seconds |
| Minimum complete epoch count | 128 |
| Minimum complete native observations | 5,000 |
| Maximum explicit pacing fraction | 60% of observation wall time |

All minimums are required. Because complete epochs have 33 calls, the 5,000
observation minimum in practice requires at least 152 complete epochs. A run
that reaches an epoch, call or wall cap quickly cannot report a hosted pass
using the unused budget as its duration. The producer does not idle at the end
to reach a duration minimum. Offered-load pacing occurs only between admitted
pairs, and its measured wait time is reported separately.

The development profile uses the same 33-call epoch, buffer sizes, native
protocol and failure cases. Its limits are one epoch, 33 attempts and 180
seconds, with no hosted-duration claim. It can report
`execution_passed=true,status=development_complete`, but never `ok=true`.
The offline validator requires an explicit `--allow-development` option to
accept such a result.

The wall values are application deadlines, not proof that an uninterruptible
kernel operation or an unscheduled Python thread can be preempted. New epochs
stop with 180 seconds of planned wall budget remaining; each new native call
also requires at least 20 seconds remaining. Existing compiler operations keep
their own bounded waits. If an operation or final identity check overruns the
total budget, the run fails qualification. No timer discards a live cleanup
owner to manufacture an on-time result.

## Exact epoch schedule

Each epoch creates a new dispatcher. It compiles the verified baseline and
submits the candidate, immediately requests cancellation, then observes the
actual build outcome. Cancellation before a build starts and cancellation
after compilation starts remain distinct receipt states. If publication won
the race, that is recorded as an unsuccessful cancellation attempt; it is not
counted as a cancelled build. At least one real cancelled publication must be
observed in a passing run.

The candidate is then staged through the public exact-rewrite boundary. The
fixed native calls are:

1. Hold one baseline call inside its actual loan, activate the candidate, and
   hold a second call on the candidate. Check both captured image identities
   and two in-flight references, then acknowledge and observe both returns.
2. Run 12 pairs on the active candidate. Buffer lengths follow the fixed
   rotation `[5, 64, 4096, 65536]`, indexed by epoch and pair number. Each normal
   call returns 55, begins with zero endpoint bytes and has the expected final
   endpoint bytes. Only endpoint values are sampled.
3. Hold two candidate calls across rollback. Check that their actual sealed
   descriptor remains open, acknowledge both, and check that the inactive
   candidate retires after their cleanup is confirmed.
4. Execute a bounds trap inside the selected loan, an allocation-refusal input
   before the loan, and a deliberately withheld ACK timeout. Retain partial
   events; no loan-end, destructor or trap cause is invented.
5. Hold two baseline calls while closing admission. The closing dispatcher
   must still count both calls. Acknowledge them, then drain and check resource
   state before the next epoch.

A complete epoch therefore has **30 returns, two traps and one timeout**.
It has 33 positively observed starts and confirmed direct-child reaps, 32
observed entries, 32 loan-begin events and 30 loan-end events. The pre-loan
SIGABRT remains an unavailable entry outcome: a silent abort does not prove
that the HIA entry was reached or identify a particular trap cause.

## Timing and resource measurements

Every attempt records its ordered ID, epoch, case, input, intended admitted
version, observed Core/artifact/generation, child PID and cleanup state,
available endpoint events, expected result, actual terminal result/error,
and admission-to-host-observation interval. A registered expected timeout is a
complete control observation only after actual cleanup confirmation.

The latency interval includes process startup, loader/configuration work,
diagnostic barriers, host scheduling, explicit lifecycle operations while a
loan is held, acknowledgement, validation and cleanup. It ends when the host
observes the terminal result, which can be later than a child completes. The
report uses nearest-rank p50/p95/p99/max on every retained attempt interval;
it is not a measurement of just the native function body. Failed runs retain
their intervals and denominators too.

Throughput is completed control observations divided by producer observation
wall time. Explicit offered-load pacing, observed public build-control wall
time, summed call-observation intervals and parent CPU seconds are separate
fields. Concurrent call intervals overlap and must not be added to wall time
as if they were disjoint. Non-pacing controller time also includes compilation,
startup, bookkeeping and OS waits; it is not native computation time.

Linux `/proc` samples record parent FD count, current RSS, address-space high
water mark and thread count before/after the run and after each drained epoch.
Child samples are attempted while the real diagnostic loan is held, with PID
and process start-time metadata and a consistency check across the read.
Unavailable/exited-process samples stay unavailable rather than becoming zero.
The report's largest observed child RSS is a sampled value, not an exhaustive
maximum. Parent FD enumeration includes its own short-lived enumeration
descriptor consistently. These samples do not account for every allocation,
all process descendants or whole-host resources.
RSS and FD stop thresholds apply at drained-epoch samples. Before/after samples
are descriptive observations, not additional threshold checks or a bound on
resource use at every instant.

The host is shared. Throughput and tail latency are descriptive; no comparison,
speedup, production deadline, network SLO or multi-machine conclusion is
awarded. Formal acceptance concerns the fixed local execution/control/resource
observations and minimum denominators, not a latency threshold.

## Failure ownership and retained evidence

All attempt and control events go to ordered `events.jsonl` records with a
previous-record SHA-256 chain. The report names the last record identity.
Content-addressed objects retain the actual sealed images used by calls,
complete build receipts and LLVM, canonical Core and the exact registration.
Identical objects are deduplicated. A cancelled image may have been discarded
by the dispatcher before the producer can copy it; its actual returned build
receipt is retained, but the producer never claims to have executed or retained
the bytes of that discarded image.

The stream records attempts before admission. Final sample records keep the
v2 distinctions between attempted calls, observed starts, confirmed reaps,
complete observations and observed native entries. A Popen failure with no
returned PID remains an unavailable start outcome; a Popen success alone does
not become a native entry. Missing outcomes cannot be filled with model claims.
All errors retain a bounded diagnostic and an identity hash.

An unexpected failure, resource threshold or evidence/disk threshold stops
new work. The current epoch is still closed and every known handle is sampled.
The separate report accounting reserve can retain current-epoch terminal rows
if the main stream refuses further writes. Use of that emergency reserve fails
qualification. It is an accounting reserve, not a filesystem guarantee against
another process filling the disk.

If a child reap cannot be confirmed, the actual dispatcher remains attached to
`NativeRuntimeSoak.host`; `drained=false` and the unconfirmed count remain
visible. Before returning a failed run, the producer starts a non-daemon
recovery thread that owns the runner and dispatcher and performs bounded
retry/close operations. Normal interpreter exit waits for this owner. If that
thread cannot be constructed or started, the caller thread performs recovery
itself. The owner-transfer boundary is the outermost `run` finalizer, covering
errors in final statistics, source/tool identity checks, checkpoint writes and
stream close. Recovery is idempotent even if thread startup raised after the
worker had already finished. Returning
`ok=false` therefore cannot silently discard the outstanding cleanup duty.

Recovery reports its own elapsed time and confirmed final drain. It never
promotes the failed qualification or rewrites its earlier sample counts.
An embedding caller may also recover through the retained dispatcher; release
remains idempotent. In an uninterruptible kernel state the recovery phase may
outlive the run's 1,800-second measurement budget, and the process deliberately
remains alive. Recovery time is a separate failure cost; the external process
record must preserve the complete actual elapsed time, including that phase.
Such an overrun is a failed profile, not hard real-time completion.
Forced process termination, host crash and durable recovery across process
loss remain outside this guarantee.

The run receipt is now `hepta.hia.native-runtime-soak.v2`. Earlier development
v1 receipts and their failing reader controls remain historical evidence.
The v2 stream has initial/final anchors for process resources, CPU counters,
observation time and total producer time; summaries are recomputed from those
anchors and the retained intervals.

The offline `validate` command delegates to `hia_runtime_soak_evidence`. It
rejects duplicate JSON keys, nonfinite numbers and incorrectly typed counts.
It verifies the registration snapshot, raw fixture and exact baseline/candidate
roles, re-verifies both Core documents and replays the registered rewrite.
It checks every fixed epoch event and call in order, including input, admitted
generation, actual result, loan endpoint events, ACK state, PID/cleanup identity,
cancellation outcome and drain state. It independently recomputes every count,
unknown/null outcome, pacing/build/call interval sum, quantile, rate and resource
summary. Build and pacing durations must fit their actual ordered event windows;
the last drained sample precedes progress and observation end. A live PID set
for held-to-terminal intervals rejects simultaneous PID reuse while allowing
sequential reuse after a call ends. Actual unique objects, journal and report
bytes are checked together against the retained-output budget. A changed hash chain or a `control_passed`
flag cannot bypass those checks. This is local evidence consistency, not
cryptographic attestation of a malicious evaluator, OS or trusted compiler.

## Register first; run only after review and source freeze

Requirements are Linux x86-64, `/proc`, sealed memfd support, `/usr/bin/python3`
and Clang 20. This producer does not compile Rust, download tools or need a
Cargo target. Existing Rust 1.90 tooling used by other gates is unaffected.
The same registered Python and Clang binaries must be used for the run.

After reviewing/committing the protocol and getting a clean source checkout,
create a new registration outside the repository:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tools/soak_hia_native_runtime.py register \
  --profile hosted-native-lifecycle-30m.v1 \
  --clang /usr/bin/clang-20 \
  --output-file /absolute/new-path/native-runtime-registration.json
```

Preserve the registration SHA-256 printed by that command. Do not recreate or
overwrite the registration after seeing an outcome. The authorized formal run
then uses that exact identity and a new output directory. Retain an outer
process record alongside stdout, stderr and the exit code. The supervising
Python process must measure monotonic elapsed time from before `Popen` until
its final `wait` returns, including retained-cleanup recovery. The producer
measurement fields exclude that later recovery; they cannot stand in for the
outer process cost. The CLI joins its recovery owner before normal return:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tools/soak_hia_native_runtime.py run \
  --registration /absolute/new-path/native-runtime-registration.json \
  --registration-sha256 EXACT_REVIEWED_REGISTRATION_SHA256 \
  --output-directory /absolute/new-path/native-runtime-hosted-run

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tools/soak_hia_native_runtime.py validate \
  --output-directory /absolute/new-path/native-runtime-hosted-run
```

Use `development-native-lifecycle.v1` for a single-epoch development receipt;
the CLI's nonzero result for that execution-only profile is intentional.
Development and negative-control outputs must be preserved separately from a
future hosted attempt. Each run keeps its first failures and stop reason.

The hard retained-output accounting limit is 96 MiB. This value was selected
before any formal registration or hosted run, after the initial development
epoch showed that 512 complete journals could exceed the draft 64 MiB cap.
The initial draft and its development evidence remain historical records.
Actual use depends on completed epochs and diagnostic error text; the single-epoch development run
should be used to report an observed size before formal submission. No 30-minute
result, production long-term qualification, Rust safety equivalence or full
P0–P7 closure follows merely from this implementation or its small controls.
