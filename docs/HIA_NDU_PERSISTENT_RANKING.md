# Bounded persistent native NDU ranking

## Observed result

The explicit persistent transport keeps one sealed native NDU process for a
bounded sequence of requests. Each request still invokes the original pinned
`evaluate_candidates_with_policy` function. The previous one-shot and prepared
APIs keep their existing process-per-request behavior.

The registered three-arm experiment completed 72 cells, 1,020 original native
evaluations and 510 ordinary controls, using 534 native processes. All 510
paired native JSON responses were byte-identical, and the same candidate was
selected by all three arms. There were zero failed cells, unstarted cells or
automatic retries.

Persistence reduced total cell cost against prepared transport at the
registered lengths of 4, 16 and 64 requests. A single-request owner was slower
in five of six comparisons. The ordinary exact scalar enumerator was faster
than persistent NDU in every paired comparison.

**P2 remains HOLD.** This is a transport optimization with a measured
single-request regression. It does not establish incremental NDU value over
the strong ordinary control or an economic benefit. Both earlier
[prepared-image campaigns](HIA_NDU_PREPARED_RANKING.md) and the historical
four-pair task campaign retain their own outcomes and source identities.

Complete original records, costs, source snapshots and independent replay are
in [the persistent evidence directory](../review-evidence/hia-ndu-persistent-20261108-5e6c/).

## Explicit transport profile

The new profile is `hepta.hia.ndu-ranking-persistent-framed.v1`. The Rust
adapter accepts it only through:

```text
hia-ndu-bridge --stream-v1 SESSION_HEX MAX_REQUESTS
```

With no arguments, the binary continues to read one JSON request through EOF,
run the existing evaluator and print its existing JSON response.

The streaming protocol has the following closed format:

| Field | Wire representation |
| --- | --- |
| Frame length | Four-byte unsigned big-endian count of the remaining frame |
| Sequence | Four-byte unsigned big-endian integer |
| Session | The caller's 64 lowercase hexadecimal characters |
| Payload | Exact original request JSON bytes, or exact native response bytes |

The greeting uses sequence zero. Request and response sequences then advance
from one without gaps or replay. The response payload includes the same
newline as one-shot output. The evaluator hashes the actual request payload,
not a parse-and-reserialize substitute. No new dependency or Cargo lock update
is required.

Both sides enforce at most 1 MiB of JSON per frame, 8 MiB of cumulative session
wire I/O and 1 through 256 requests per owner. Rust checks a frame's declared
length before allocating its body, refuses a partial header or body, and
checks session and sequence before parsing or evaluating JSON. EOF at a frame
boundary requests clean close; EOF within a frame refuses. The native process
exits once its startup request allowance has been evaluated.

The Rust loop constructs a new request, contributions, profile and policy for
every accepted frame and calls the original evaluator. Its retained state is
the explicit transport session, count and byte allowance. There is no result
cache or shortcut replacing NDU with ordinary enumeration.

## Python ownership and final close

```python
from hepta.hia_ndu_persistent_ranker import PersistentNduRanker

owner = PersistentNduRanker(
    {"binary": binary_path, "build_receipt": build_receipt_path},
    max_requests=len(requests),
    lifetime_s=30.0,
    startup_timeout_s=1.0,
    observer=record_original_event,
)
with owner:
    responses = [owner.rank(request, timeout_s=1.0) for request in requests]
receipt = owner.receipt()
assert receipt["complete"] and receipt["session_accepted"]
```

A round's response remains advisory until the entire owner closes successfully.
Unexpected bytes can appear after an apparently valid frame; the next round
or final close must detect them. A caller must not treat an unclosed owner as
a completed qualification.

Preparation uses the existing exact build admission and actual sealed Linux
memfd image. Calls check the retained descriptor identity and mandatory seals.
Changing the origin pathname does not replace the admitted running image.
The new owner composes the existing sealed-image owner and does not change
the prepared API's semantics.

The process starts in its own session. Calls serialize through one owner;
reentrant calls and closing during an active observer refuse. Actual input
bytes are frozen before writing, so mutation of the caller's dictionary cannot
change request/response validation.

The startup deadline is checked before process launch. Each round has its own
remaining deadline, including elapsed lock waiting, and the session has a
maximum 60-second configured lifetime. A watchdog retires the process even if
the owner is idle. OS calls, lock waiting, scheduling and cleanup are not hard
real-time reservations.

Process ownership uses Linux `waitid(WNOWAIT)`. The leader remains unreaped
while its numeric process-group identity is used. Explicit close and the
watchdog share one guarded transition: confirm the child, signal its process
group, then reap the original leader. That transition is attempted once.
External reaping, a failed signal or an unconfirmed wait cannot produce a
successful cleanup receipt or cause a second signal against a possibly reused
PID.

Normal close sends input EOF, checks final output EOF and a zero exit status,
performs group cleanup, joins the watchdog, closes pipes and releases the
sealed descriptor. Failure retires the owner without retry. A close protocol
failure or observer failure leaves `session_accepted=false`. A failed session
can have `complete=true` for its measured costs when cleanup is confirmed;
cost completeness is distinct from successful session acceptance.

The kernel, loader/interpreter, shared libraries, process environment and
trusted local build receipt remain assumptions. This transport is not a
malicious-binary sandbox, host attestation or machine correctness proof.

## Costs and registered comparison

Owner receipts include preparation, serialized admitted rounds including
observer work, and explicit close. The inner sealed-image preparation and
close, process cleanup and timer work are nested in these observed intervals;
their totals are not added again. Per-caller queue waiting is recorded
separately because it overlaps other work.

Constructor failure has no returned owner for ordinary callers. The outer
attempt must retain its elapsed time and failure observations. The experiment
measures the complete outer cell from before preparation through all original
I/O recording, decision checks, close, receipt generation and original stream
close. Cell-summary writing occurs outside the cell but inside the campaign
interval. Registration, acquisition and the retained native build have separate
records.

The experiment registered all requests, source files, orders and budgets before
measurement. Its three arms were prepared NDU, persistent NDU and the same
independent ordinary scalar enumerator used in the earlier experiments. Each
horizon used all six permutations of these arms. The four horizons, 1, 4, 16
and 64, were fixed before execution. Inputs included 2, 8 and 32 candidates,
unique minima, ties, infeasible alternatives and resource limits.

The ordinary arm receives the same supplied costs and feasibility constraints
and computes the exact scalar minimum with the same incumbent-first tie rule.
It is not charged for an unnecessary native process and is not relabeled as
NDU. All arms include the same independent selection check and their actual
evidence-recording work.

The campaign ceiling was 120 seconds, with at most 1,020 native evaluations,
534 native processes and 510 ordinary calls. Native rounds and startup had a
one-second remaining timeout; each persistent owner had at most a 60-second
lifetime. The registered campaign had no warm-up or retry. Native protocol
functional checks had already run before registration, and host caches were
not reset or independently measured.

Registration SHA-256:
`4fc7b9a02c26d8641f658975f7ed481a08b5dba8b094407aa38f73405a46c9c7`.

The registration froze at 2026-11-08 17:54:38 UTC and its complete Git blob was
checkpointed before execution. Measurement ran from 17:55:38 to 17:55:40 UTC.
Campaign wall time through summary preparation was 2.427904998 seconds;
registration preparation cost 17.708620 ms.

The host was shared. Collaborating Core and ABI tasks confirmed that they had
no running local compilation or tests before the short measurement window.
Unrelated sessions were not excluded. Counterbalanced order does not establish
stationarity or authenticate clocks.

### Every registered horizon

Each cell includes its owner preparation and close. The table gives medians
over six orders. Aggregate reduction uses the sum of all cell costs at that
horizon, rather than a ratio of medians.

| Requests per owner | Ordinary (ms) | Prepared NDU (ms) | Persistent NDU (ms) | Persistent faster pairs | Aggregate reduction vs prepared |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.107843 | 6.065478 | 6.698724 | 1/6 | −5.50% |
| 4 | 0.442638 | 12.802330 | 10.330672 | 6/6 | 20.33% |
| 16 | 2.171921 | 43.734495 | 28.328367 | 6/6 | 33.72% |
| 64 | 8.235227 | 168.205296 | 94.701037 | 6/6 | 45.17% |

The per-pair prepared-minus-persistent saving ranges were
−1.763230 to 1.081100 ms, 1.744732 to 3.939823 ms,
12.523300 to 18.068322 ms and 58.282968 to 95.414622 ms.
No pair is discarded. The ordinary control won all 24 comparisons with
persistent NDU. These four horizons do not establish an unmeasured general
break-even threshold.

The independent standard-library replayer checked 14 frozen source files,
every original frame's length, session, sequence and payload, all 534 observed
process identities, final EOF/cleanup, scalar selections, cost arithmetic and
reported paired statistics. All 510 persistent native response payloads were
byte-identical to the corresponding prepared-native stdout. Replaying these
records does not rerun the evaluator or independently authenticate timing.

## Exact native provenance and tests

The new Rust source was first built in isolated branch
`codex/hia-ndu-scalar-stream-5e6c-20261108`, commit
`af8a07ee07b588e2c10eab63ed364f3387c2fc2e`, by
[CI run 42505864233](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42505864233).

| Item | Identity |
| --- | --- |
| Artifact | `13627467066` |
| Artifact ZIP SHA-256 | `ba5e02ecf0337dfb04bad2f8eaee3f5a7fc408330beada5e36fc78dd5898bb9f` |
| Native executable SHA-256 | `494d198e94f533c8a894dc141a42be2890fa12bce14d9b4b2c849ee5fbf46cb5` |
| Executable size | 2,345,848 bytes |
| Pinned upstream NDU commit | `d3c2d760eca5065fc966820379c35c6e8d56e855` |
| Build receipt SHA-256 | `4f1f83cf63773deb6ad2dd73f59b74cdd06a83fce4a3234a83b11d50bd59200a` |
| Native adapter source SHA-256 | `cf61b6055fb7299d661092d7e75a3e5c05125b780cbca72545f2de717bf4f574` |

The artifact ZIP, executable, build receipt and actual local adapter source
were checked before use. The retained native build cost was 22.158240725
seconds with the builder's stated boundaries. It is disclosed once and not
charged again to every cell. No provider/model calls were made; monetary,
energy, development, environment recovery and complete lifecycle costs remain
unknown.

The final local suite passed 62 tests with zero skips in 2.598 seconds. It
includes 22 new tests (three against this real native artifact), plus the
40 existing prepared/one-shot/budget controls:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest \
  tests.test_hia_ndu_persistent_ranker \
  tests.test_hia_ndu_prepared_ranker \
  tests.test_hia_ndu_optimizer_transport \
  tests.test_hia_ndu_optimizer_budget.RankingBudgetTests -v
```

For the native cases, `HEPTA_NDU_BRIDGE` and `HEPTA_NDU_BUILD` must point to
the new built artifact and its receipt directory. The new controls exercise
actual process persistence, fresh evaluation of identical requests, snapshot
binding, partial/oversized frames, session/sequence replay, timeouts, idle
watchdog retirement, external reaping, attempt and aggregate wire caps,
concurrency, context entry and startup/round/close observer failures. Fixture
tests are explicitly distinct from original NDU checks.

The Rust source also includes three framing unit tests for size/budget limits,
partial frames and session/round replay. The first build compiled production
Rust only; these three unit tests require the explicit Cargo test command
below and are not counted in the local 62-test result.

## CI and reproduction

The existing native workflow builds the exact pinned upstream source and sets
`HEPTA_NDU_BRIDGE` and `HEPTA_NDU_BUILD`. Its built workspace can run the Rust
framing unit tests without adding dependencies:

```sh
"$(rustup which --toolchain 1.95.0 cargo)" test \
  --manifest-path "$HEPTA_NDU_BUILD/Cargo.toml" \
  -p hia-ndu-bridge --locked
```

Use the same configured `RUSTC` and `CARGO_TARGET_DIR` as the native build.
Add the Python persistent test module to the existing workflow suite. Then,
from a clean committed checkout:

```sh
hia_persistent_output="$RUNNER_TEMP/hia-ndu-scalar/persistent-ranking"
python -B tools/qualify_hia_ndu_persistent_ranker.py register \
  --binary "$HEPTA_NDU_BRIDGE" \
  --build-receipt "$HEPTA_NDU_BUILD/build-receipt.json" \
  --output "$hia_persistent_output"
hia_persistent_registration=$(cat "$hia_persistent_output/registration.sha256")
python -B tools/qualify_hia_ndu_persistent_ranker.py run \
  --directory "$hia_persistent_output" \
  --registration-sha256 "$hia_persistent_registration"
python -B tools/replay_hia_ndu_persistent_ranker.py \
  --directory "$hia_persistent_output" \
  --registration-sha256 "$hia_persistent_registration" \
  --output "$hia_persistent_output/replay.json"
```

The existing always-upload artifact path retains this complete directory,
including original framed bytes, all cell journals, frozen source and build
receipt. The independent replayer can also audit the retained archive without
the native executable or this isolated local Git checkout.

This profile is opt-in and is not silently activated in the macro Agent
lifecycle. Its remaining engineering burden and the observed ordinary-control
advantage are part of the outcome, not grounds to lower the P2 acceptance
criteria.

## Later source-bound CI observation: 14b2c03c

The [complete retained 14b2c03c campaign](../review-evidence/hia-ndu-14b-ci-20261108-5e6c/README.md)
contains 72 completed cells, no failed or unstarted cells, no automatic retries,
1,020 native responses from 534 processes, and 510 byte-identical native-response
pairs. At horizon one, persistent transport won 2/6 pairs and its aggregate
saving against prepared was +1.077%; this differs from the earlier retained
50c1578b negative aggregate and 1/6 wins. Both observations remain available.
Horizons 4, 16 and 64 each had 6/6 persistent wins against prepared, with
aggregate savings of 15.668%, 33.425% and 43.626% respectively.

The ordinary scalar control was faster in all 24 pairs again. The independent
replay checks original frames, identities and cost arithmetic without claiming
authenticated timings. The original reports retain `model_cost: null`,
incomplete full cost and P2 HOLD. The 172-test Python integration and three Rust
framing controls are finite software gates; neither this successful workflow
nor the mechanism measurements replace the separately failed cold source gate
or establish economic benefit.
