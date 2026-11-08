# Explicit sealed-image reuse for NDU ranking

## Result and scope

The caller-owned `PreparedNduRanker` removes repeated admission and sealing of
the same native executable while still starting, observing and reaping a new
original NDU process for every request. This is an opt-in transport profile,
`hepta.hia.ndu-ranking-prepared-sealed.v1`. It does not alter the native ranking
algorithm or the existing one-shot and macro policy APIs.

The final-source mechanism experiment completed all 72 registered cells with
1,020 native process invocations, 510 ordinary control calls and no failed cells
or automatic retries. Prepared transport cost less than one-shot transport in
all 24 paired comparisons. The ordinary scalar control was faster than both
native arms in every paired comparison and selected the same candidate.

**P2 remains HOLD.** These observations establish a local transport-cost
reduction for the disclosed finite supplied-cost workload. They do not establish
incremental NDU value over the ordinary control, real-task productivity,
full-lifecycle cost recovery or economic benefit. The prior four-pair task
campaign, in which only one pair was faster overall, is not overwritten or
reinterpreted by this separate mechanism experiment.

The complete recorded evidence is in
[`review-evidence/hia-ndu-prepared-20261108-5e6c/`](../review-evidence/hia-ndu-prepared-20261108-5e6c/).
Both completed mechanism runs are retained, including the earlier source
version, the final source rerun and a rejected registration attempt before any
native execution.

## Why this change exists

The one-shot caller validates the native source/build receipt, reads and hashes
the executable, copies it into a sealed executable descriptor, runs the child
and checks the mutable original path after each request. That behavior is
appropriate when the caller requires a new admission and current path binding
for every call. Repeating it for a retained 2,286,848-byte executable also
introduces a measurable fixed cost.

A prepared owner validates the existing exact build identity once and retains
the actual immutable executable bytes in a sealed Linux memfd. Each call
requires the same descriptor device, inode, size, mode and all four mandatory
kernel seals before and after execution. A pathname, modification time or
cached filename is never sufficient to admit a call.

This explicitly changes the binding lifetime: replacing the original path
after preparation cannot replace the executable owned by the prepared handle.
The owner continues using the originally admitted bytes. The old one-shot
caller keeps its existing current-path checks. A caller that requires a newly
admitted executable or updated source creates a new owner and charges that
preparation separately.

## API and ownership

```python
from hepta.hia_ndu_prepared_ranker import PreparedNduRanker

bridge = {
    "binary": "/absolute/path/to/hia-ndu-bridge",
    "build_receipt": "/absolute/path/to/build-receipt.json",
}

owner = PreparedNduRanker(bridge, max_requests=64)
with owner:
    for request in requests:
        response, identity = owner.rank(request, timeout_s=1.0)
receipt = owner.receipt()  # Read after close to observe a completed owner.
```

The owner has an explicit allowance of 1 through 256 admitted attempts. Every
attempt uses the existing bounded child-process transport, with original input,
output, process observations and cleanup available through an observer callback.
Responses and processes are never cached or reused.

Calls on an owner are serialized. Reentrant invocation and closing during an
active observer are rejected. The request is frozen into the actual submitted
wire bytes, so subsequent mutation of the caller's dictionary cannot change
which request a response is checked against. A failed admitted call retires the
owner and performs its close path; it does not retry. Context-entry validation
failure also closes the owner before propagating the failure.

The timeout includes elapsed serialization and lock waiting when determining
whether a process may start. Lock waiting, OS process creation and cleanup do
not constitute a hard real-time deadline. A caller needing stronger resource or
scheduling guarantees needs a separately validated execution boundary.

The trusted local receipt, Linux kernel and descriptor seals, loader or
interpreter, shared libraries, process environment and in-process ownership
remain assumptions. Executable byte identity is not host attestation or a
machine-level proof of the runtime, the loader or the NDU algorithm.

## Cost accounting

The prepared receipt records preparation, every admitted attempt (including
failures and observer work), native process starts and cleanup, and close.
Preparation plus serialized attempt service intervals plus close are disjoint.
Per-caller queue waiting is reported separately because those intervals can
overlap other calls and cannot be added to a disjoint owner total.

A receipt is incomplete while the owner is live, when an attempt lacks its
terminal timing, or when close or native cleanup has not been confirmed. If the
descriptor number has been reused by outside code, the owner refuses to close
the unrelated descriptor and leaves its close receipt incomplete. It never
silently retries an uncertain close.

Rejected calls before attempt admission, constructor failures with no returned
owner, caller startup, source acquisition, builds, between-call work and final
receipt serialization require an outer caller measurement. Therefore the
receipt always reports `whole_lifecycle_cost_complete=false` and
`economic_benefit_established=false`.

The mechanism runner measures each cell from before owner preparation through
all original response observation, selection checks, actual attempt records,
close and receipt generation. Per-cell summaries are written outside that
cell's interval but inside the campaign interval. Nested cell totals are not
added to the outer campaign time again. The runner keeps unsuccessful and
unstarted cells if the frozen budget is exhausted.

Prepared ownership is not silently inserted into `advise_macro`: that existing
ledger would need to own and charge acquisition, preparation, reuse and close
before a macro-level integration could claim a complete lifecycle.

## Frozen experiment

The protocol registers every request, all source hashes, native identity,
budgets and arm order before measured execution. It uses no random seed,
warm-up selection, automatic retry or post-hoc acceptance threshold.

- Request horizons are 1, 4, 16 and 64.
- Each horizon uses all six permutations of the three arms: one-shot NDU,
  prepared NDU and ordinary scalar.
- All arms receive the same frozen finite supplied-cost inputs. They cover
  candidate counts 2, 8 and 32, unique minima, incumbent and non-incumbent ties,
  infeasible alternatives and a resource cap.
- The ordinary arm independently enumerates feasible candidates, takes the
  exact scalar minimum and uses the same incumbent-first tie rule. Its work is
  not relabeled as NDU.
- A native call has at most one second of remaining admission budget. The
  campaign budget is 120 seconds, with at most 1,020 native calls and 510
  ordinary calls.
- All outcomes and paired differences are reported. Statistics are descriptive;
  there is no preregistered significance or economic-success test.

The shared host was not exclusive. The collaborating Core and ABI tasks paused
their CPU-heavy work during measurement, but unrelated sessions and host load
were not excluded. Counterbalanced arm order reduces one scheduling bias; it
does not establish stationarity or authenticate elapsed times.

### Final-source observations

Final registration SHA-256:
`24e435dffef293e1f785094620630eacdfd39bf48957e20c4a4706136cfba66b`.

Registration froze at 2026-11-08 17:19:48 UTC. The full registration blob was
checkpointed before execution; the measured campaign started at 17:24:30 UTC
and ended at 17:24:38 UTC. Its observed wall time through summary preparation
was 7.935808831 seconds. Registration preparation itself cost 37.259701 ms.

Each row below reports the median complete cell cost over the six arm orders,
including prepared acquisition and close. The final column is the percentage
reduction in the sum of prepared versus one-shot cell costs at that horizon,
not a ratio of medians.

| Requests per owner | Ordinary scalar (ms) | One-shot NDU (ms) | Prepared NDU (ms) | Prepared vs one-shot aggregate reduction |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0.083912 | 9.050001 | 6.427090 | 30.64% |
| 4 | 0.322562 | 37.153698 | 13.646979 | 65.38% |
| 16 | 2.003893 | 175.989572 | 55.760345 | 69.23% |
| 64 | 5.189478 | 776.775859 | 212.694964 | 73.02% |

Every horizon retained all six observations. The one-shot-minus-prepared
saving ranges were 1.641416–4.657184 ms, 21.742088–31.460092 ms,
98.755717–159.195060 ms and 434.654486–760.752324 ms respectively.
The ordinary arm remained faster in every pair.

The standard-library-only independent replayer rehashed ten frozen source
files, all requests, original response bytes and result bindings, and replayed
selection, process cleanup and cost arithmetic. It verified 1,020 distinct
observed process IDs and 510 byte-identical paired native responses. It does
not execute the native artifact again or independently authenticate the clock.

### Earlier run and unsuccessful setup

The earlier complete registration was
`d49ef0292bb7be35d7d709f1b493d543eeb9295163a85bf184b8942d3670370e`.
It completed the same 72 cells, 1,020 native calls and 510 ordinary calls in
6.718958480 seconds, with no failed cell or retry. Registration preparation
cost 12.255089 ms. Its ordinary / one-shot / prepared median cell costs (ms)
were:

| Requests per owner | Ordinary scalar | One-shot NDU | Prepared NDU |
| ---: | ---: | ---: | ---: |
| 1 | 0.142390 | 9.001107 | 6.881009 |
| 4 | 0.365045 | 37.727534 | 14.243977 |
| 16 | 2.172462 | 161.336474 | 44.619662 |
| 64 | 5.470291 | 642.939318 | 165.082591 |

That run also favored prepared over one-shot in all 24 pairs while ordinary
won every pair. It remains evidence for its own source snapshot.

A subsequent source review found that context-entry validation failure could
leave the prepared descriptor open. The owner now closes on that path, and a
regression test observes the actual descriptor close. The independent replay
tool and automatic source snapshot retention were also completed. The final
run repeats the same disclosed inputs and orders against these final source
bytes; it is not substituted for the earlier observations.

Before the final run, a registration was rejected because an isolated recovery
baseline accidentally tracked generated Python bytecode. A child in the
transport tests changed that cache, so the clean-source gate refused to
register. Zero native calls ran. Generated caches were removed from that local
source snapshot and ignored; the gate was preserved. The retained diagnostic
is reconstructed from tool output and does not have a complete original setup
timer. Environment recovery, development, source acquisition and this failed
setup are not assigned zero cost.

## Native artifact provenance

The experiment used the original native artifact from
[workflow run 42497221815](https://github.com/TrillionniumFoundation/Hepta/actions/runs/42497221815),
artifact `13624221619`,
`hia-ndu-scalar-selection-321daf28ef230a532f0f382469a9f6fc4f4fa249`.

- Hepta source commit:
  `321daf28ef230a532f0f382469a9f6fc4f4fa249`.
- Pinned upstream NDU commit:
  `d3c2d760eca5065fc966820379c35c6e8d56e855`.
- Downloaded artifact ZIP SHA-256:
  `b7bb88bf06a28d1fb695240584878127a7ffaabb181a16a8acd7e75c2a48a2ae`.
- Executable SHA-256:
  `b32b71c543a6bae9c56445598d71751dcdbebdc7cca05e0c0850254c4e7cd336`.
- Original build receipt SHA-256:
  `b28edcd3acd71bea738c19f40bfd61685738623325b3d17b216144fa161ce885`.

The original build receipt records 24.417420876 seconds of build wall time
with its own stated boundaries. This retained historical build is disclosed
separately; it is neither charged repeatedly to each cell nor represented as a
new local build. Full acquisition, engineering, energy and monetary costs are
unknown. The experiment made zero provider/model calls.

## Verification and reproduction

### Review repair: bind the reported paired analysis

The earlier independent replayer checked retained cell ledgers but did not
compare the report's `analysis` with those ledgers. An actual review
counterexample changed a paired difference and its horizon summary sum to
`-999999999999999999`; the earlier replayer still accepted it. The original
report, altered copy, both original verifier results and the repaired verifier
results remain in
[`review-evidence/hia-ndu-prepared-replay-50c-20261108-5e6c/`](../review-evidence/hia-ndu-prepared-replay-50c-20261108-5e6c/).

The repaired replayer requires all 72 registered cells, reconstructs the 24
paired comparisons from their recorded costs, and recomputes every reported
horizon statistic. It compares the complete canonical JSON analysis, including
order, labels, field sets and exact JSON number types. Missing, extra,
reordered, relabeled or altered results are refused, including Boolean or
floating-point values that Python would otherwise compare equal to integers.
The unchanged original CI report passes; the same corrupted copy now exits
unsuccessfully and receives no successful replay receipt.

The complete prepared-ranker suite passes 23 tests, including eight new
analysis tests with 204 negative subcases. These are checker regressions and
replay of retained measurements; no new timing experiment or economic result
is claimed. Recorded elapsed times remain unauthenticated observations and P2
remains HOLD. The earlier source-bound measurements and 40-test result below
remain historical evidence for their stated source snapshot.

### Original mechanism qualification

The final local focused suite passed 40 tests with zero skips:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B -m unittest \
  tests.test_hia_ndu_prepared_ranker \
  tests.test_hia_ndu_optimizer_transport \
  tests.test_hia_ndu_optimizer_budget.RankingBudgetTests -v
```

Fifteen new tests cover snapshot identity and changed paths, actual sealed
descriptor ownership, frozen request binding, byte replay rejection, original
child failures, timeout cleanup, bounded I/O, attempt limits, concurrency,
reentrant observers, context-entry close and cost accounting. Fixture children
exercise the real Linux transport, but these tests are not described as
original NDU execution. That identity is established by the separate native
campaign.

Two existing real-Z3 budget tests were not run in this restored local
environment, which lacked Z3. They are outside the reported 40-test command;
they are not counted as passes or skips. The existing native CI workflow
installs its pinned Z3 dependency and can run the entire test modules.

The existing `.github/workflows/hia-ndu-scalar-selection.yml` builds the pinned
upstream source with `tools/build_hia_ndu_bridge.py`. It sets
`HEPTA_NDU_BRIDGE` to the actual compiled binary and `HEPTA_NDU_BUILD` to the
directory containing its build receipt. From a clean committed checkout,
register a new output directory, preserve the printed digest before execution
and run exactly that registration:

```sh
hia_prepared_output="$RUNNER_TEMP/hia-ndu-scalar/prepared-ranking"
python -B tools/qualify_hia_ndu_prepared_ranker.py register \
  --binary "$HEPTA_NDU_BRIDGE" \
  --build-receipt "$HEPTA_NDU_BUILD/build-receipt.json" \
  --output "$hia_prepared_output"
hia_prepared_registration=$(cat "$hia_prepared_output/registration.sha256")
python -B tools/qualify_hia_ndu_prepared_ranker.py run \
  --directory "$hia_prepared_output" \
  --registration-sha256 "$hia_prepared_registration"
python -B tools/replay_hia_ndu_prepared_ranker.py \
  --directory "$hia_prepared_output" \
  --registration-sha256 "$hia_prepared_registration" \
  --output "$hia_prepared_output/replay.json"
```

The directory includes all original call records, cell journals, frozen source,
the original build receipt and summary. The workflow's existing always-upload
artifact path contains this subdirectory. A completed timing experiment is not
a performance acceptance gate; its output retains `p2_acceptance="HOLD"`.

An auditor can unpack either retained campaign archive and run the independent
replayer against that directory and its registration digest without executing
NDU or trusting this document's rounded timing table. The replay code itself
is pinned by the verifier SHA-256 in each report. The native logs, local
measurements and independent arithmetic check remain scoped evidence; they do
not authorize production activation or assert a global safety property.
