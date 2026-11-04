# Fixed raw-model four-arm service-cost protocol v1

`tools/measure_hia_raw_session_cost.py` freezes and measures one specific
comparison. Implementing this protocol is not a measurement result. The tool
does not build the native adapter or execute a selected application.

## Question and arms

The comparison separates process reuse from the additional NDU evaluation.
Every arm receives the same raw model and uses the same actual release binary,
upstream source identity, adapter source inventory and build receipt.

| Arm | Entry point | Native mode | Process lifetime |
| --- | --- | --- | --- |
| `one_shot_exact_dp` | `hia_ndu_raw_model.invoke` | `exact_dp` | One fresh process per request |
| `one_shot_ndu` | `hia_ndu_raw_model.invoke` | `ndu` | One fresh process per request |
| `session_exact_dp` | `RawModelSession.evaluate` | `exact_dp` | Three sessions: 256, 256, 232 requests |
| `session_ndu` | `RawModelSession.evaluate` | `ndu` | Three sessions: 256, 256, 232 requests |

Both native modes reconstruct and search the model in Rust on every request.
Only `ndu` invokes the original NDU evaluation after the shared search. The
Python APIs perform admission and witness replay; the study does not invoke a
Python continuation search. A session reuses transport and its sealed executable,
not a previously computed model, plan or result. Each session arm owns separate
processes. The existing default sealed-image checks remain enabled.

## Fixed workload and ordering

The 24 models are returned without modification by
`tools.measure_hia_raw_model_cost.cases()`: six fixed families at horizons 1–4.
There are exactly 31 rounds, 744 requests per arm, and 2,976 total decisions.
The model's declared decision costs remain identical in all four arms. They
are model inputs, not a substitute for the measured service clocks.

Cases retain their fixed order. For each `(round, case_index)` quartet, the
arm order is the table order when their sum is even and its reverse when odd.
This also alternates the order of the two modes and the two transport paths.
The protocol does not claim that this removes every scheduling or cache effect.
There are no warmup calls, extra identity probes, dropped outliers, failed-slot
retries, adaptive workload choices or performance-based early stopping.

The entire cases table, 2,976-slot schedule, segment/sequence assignments and
analysis rules are written into a create-only `REGISTRATION.json` before any
native decision. `run` rejects a definition differing from the fixed one,
including JSON boolean/number substitutions. The registration also binds the
committed source HEAD/tree and relevant files, executable hash, build receipt
hash and original compiler-stream identities when build timing is available.
The same input checks run after the last operation. Changed inputs cannot
produce a complete measurement.

## Cost boundaries

All primary operation clocks use `time.monotonic_ns()` immediately outside the
public API call, stopping after its return. This includes construction of the
returned receipt and Python function exit. The API's own reported clock is
retained as a secondary observation and never replaces that outer clock.

For a session arm, the registered service total is:

`sum(three complete constructors) + sum(744 complete evaluate calls) + sum(three complete closes)`.

The constructor includes source/manifest admission, image pinning, child launch,
handshake and image checks. Close is timed separately through its return. The
tool also observes the actual child return code, descriptor release, pipe
closure and cleanup diagnostics. A normal completed segment requires a reaped
child with exit status zero and released descriptors. Each session closes as
soon as its registered segment ends; the next is created when its next slot is
reached. The final segment contains exactly 232 calls.

For a one-shot arm, its 744 complete `invoke` calls already contain image
preparation, process launch, native work, parsing/witness admission, process
reaping and descriptor release. Its separate startup and close terms are
therefore zero, explicitly marked as included in the call. They are not
unmeasured work and are not charged twice.

The report includes call mean, median, p95, p99 and maximum, as well as separate
startup/close observations and the service total. Call percentiles describe
the call boundary; they are not application tail latency or amortized startup
percentiles. Session `snapshot()["requests"]` is a received-response sequence,
not an attempted-work counter. Attempts and elapsed costs come from the outer
measurement records even when a timeout leaves that sequence unchanged.

Build accounting reuses the existing `build_cost_observation` admission,
including successful-build status, valid positive timing, original stdout/stderr
hashes and their on-disk bytes. A malformed present cost refuses registration.
An inherited receipt without measured build time keeps `B = null`; it never
becomes zero. The same observed build `B` is charged once to **each standalone
arm alternative**, with `B / 744` per request. It is not divided by four.
Build-inclusive totals remain null if `B` is unknown or the campaign is
incomplete. A fully cold machine is not claimed.

Caller logging, additional measurement audits, imports, acquisition outside the
recorded build and execution of a selected optimized program are outside the
service total. A separate campaign wall clock records the measurement harness
through analysis and compression, excluding final report writing. Neither
metric establishes a complete application-lifecycle advantage.

## Equality, failures and retained evidence

For every round/case quartet, all six arm pairs compare every field of the
complete `bundle`, ordered `pareto_candidate_ids` and `selected_first_action`.
Comparison uses canonical, type-sensitive JSON, so `false`, `0`, `0.0` and
missing values are not silently equated. Different native mode/provenance and
timing fields are expected and are not treated as decision differences.

Every attempted startup, request and close has a start and finish record in
`ORIGINAL.jsonl`, flushed after each write. Successful call records retain the
complete original API receipt, including original response text and request
bytes. Startup records retain the observed handshake frame. Equality records
retain all six comparisons and per-field hashes. Errors retain exception type,
message, traceback and any exception-exposed output bytes in base64. Session
snapshots retain available stderr and cleanup diagnostics; a last frame after a
failure is explicitly labelled as possibly belonging to a prior request.

The existing APIs do not expose every original native stream on every failure.
For example, a rejected one-shot call can expose only a bounded stderr excerpt,
and a failed constructor does not return its session. Such missing stream data
is labelled unavailable. The tool neither reconstructs those bytes nor claims
complete native-stream capture for those failures. Every available measurement
record and error is retained; neither runtime is modified for the study.

The first startup, call, receipt-binding, equality or close failure stops new
requests. Already acquired sessions are closed, with all additional cleanup
errors retained alongside the original failure. Failed requests are never
replayed, and a close attempt is not retried after an uncertain outcome. The
report lists attempted, failed and unattempted calls. Partial observed time is
retained, but full standalone service totals and ratios are null. Completion
requires all 2,976 calls, all 744 equal quartets, all six normal session
lifetimes and unchanged registered inputs.

The output directory contains the original `REGISTRATION.json`, all
`ORIGINAL.jsonl` records, a lossless deterministic `ORIGINAL.jsonl.gz`,
`ERRORS.json` and `RESULT.json`. Existing measurement output prevents replay
into the same directory. Abrupt process/host loss can leave an incomplete log;
it is not a complete run merely because some calls succeeded.

## Analysis and execution

The four predefined descriptive comparisons are session DP / one-shot DP,
session NDU / one-shot NDU, one-shot NDU / one-shot DP, and session NDU / session
DP. Their denominator and numerator are complete registered service totals.
This protocol does not select a best-looking comparison after measurement,
compute a confidence interval, or assert an independent-host population result.
The 31 consecutive rounds remain observations from one fixed campaign.

Commit the measurement sources before freezing. Use an output directory outside
the source checkout and the already recorded source-preserving release build:

```sh
python3 tools/measure_hia_raw_session_cost.py freeze \
  --binary /absolute/path/to/hia-ndu-raw-model \
  --build /absolute/path/to/build-receipt.json \
  --output /absolute/path/to/new-four-arm-study
python3 tools/measure_hia_raw_session_cost.py run \
  --output /absolute/path/to/new-four-arm-study
```

`freeze` performs no native decisions. `run` exits nonzero for incomplete
measurement. Neither command rebuilds, activates a selected program, changes
controller defaults, or grants a safety certificate. The small unit controls
use synthetic clocks and in-memory API substitutes; they validate the protocol
and accounting, and supply no performance evidence.
