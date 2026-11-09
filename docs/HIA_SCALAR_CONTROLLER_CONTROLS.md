# Frozen identical-pool scalar controller controls

`tools/measure_hia_scalar_controller_controls.py` isolates the cost of the
existing strong ordinary selector and the source-bound native NDU selector.
Each pair receives exactly the same candidate table, remaining allowance,
objective digest and generation. It does not rerun proposal generation or
candidate timing separately for the two arms.

The current scalar profile supplies one conservative cost axis. The ordinary
selector enumerates its minimum. The native evaluator returns the same
minimum-cost frontier and the caller uses the same incumbent-first, then
lexicographic tie rule. A successful native response therefore introduces no
additional decision information in this profile. This study checks the actual
wire relation and measures its complete invocation costs. It does not claim a
general NDU impossibility result or an economic benefit.

## Fixed design

The protocol schedules exactly **64 pairs and 128 selector calls**, using eight
specified scenarios repeated eight times:

| Scenario | Expected choice or boundary |
| --- | --- |
| Unique cheaper challenger | Select the unique cheaper candidate. |
| Unique incumbent minimum | Retain the incumbent. |
| Incumbent on a tied frontier | Retain the incumbent. |
| Two cheaper tied alternatives | Select the first lexicographic alternative. |
| All three tied | Retain the non-lexicographic incumbent. |
| Cheaper candidate fails quality | Exclude that candidate. |
| Candidate exceeds the resource cap | Exclude that candidate. |
| Cost plus uncertainty equals the cap | Admit the boundary incumbent and reject one nanosecond above it. |

Every scheduled case has a feasible incumbent, so all 64 NDU calls must invoke
the actual native evaluator. Empty feasible sets and zero budgets are separate
no-dispatch regression tests; they cannot inflate the native-call count.
The deterministic rotated order has 32 ordinary-first and 32 native-first
pairs, with four of each per scenario. There is no warmup exclusion, sample
extension, replacement or automatic retry. One exception, inconsistent reply,
changed input or unsettled cleanup freezes all later calls.

The primary outcome is completion with the same specified choice and an
independent check of the original native request, response, executable identity
and cleanup. Secondary outcomes are descriptive paired wall and parent/child
CPU costs. These are repeated invocations on one host, not independent
training runs or a real-task sample. No population confidence interval or
causal downstream task benefit is inferred.

## What is charged

The timed interval covers the complete existing `checked_pool_selection` call.
For NDU this includes the original native build-receipt and executable
admission, image reads, `memfd` sealing, bounded process, request and reply
checks, deterministic caller tie handling and in-memory observer capture.
The ordinary call follows the same existing selector API and receives the
same frozen values.

Raw evidence writes and offline auditing occur outside both timed calls.
Their costs remain in the reported outer interval, together with source/native
admission. Nested native and call times are not added to that outer interval
again. Failed attempted calls retain their measured costs. An unstarted arm
has unknown cost (`null`), not zero; an incomplete pair has no paired delta.
The native timeout is the existing software budget check, not a hard physical
OS quota.

Prior source acquisition, the original native build, authoring, provider fees,
the final summary write and artifact upload are outside this measurement.
Their omission is explicit; money stays unknown and full economic cost remains
incomplete. Quality flags, costs and artifact identities are authored table
inputs. No candidate artifact is compiled, adopted or used as a real task.

## Source and native identity

Preparation accepts an explicit source HEAD and freezes every imported local
Python source, the native adapter inventory, the builder and the harness.
It retains the exact input bytes, the base commit/tree and all working-file
bytes. This permits honest development measurements before publication without
requiring a commit to contain its own future result. It never calls a dirty
checkout a clean commit qualification. Source inputs and native identity are
checked again before and after the run.

The native executable and original build receipt are copied byte-for-byte into
the evidence object store. Admission uses the existing `_bridge_identity`
contract, including the exact adapter, builder, lockfile and executable hashes.
Optional `--native-provenance` retains the original CI artifact metadata or
same-workflow build context. This is trusted-host provenance, not remote
attestation. The workflow builds the pinned evaluator on the actual tested
commit and produces a new plan for that commit.

## Commands

Use a new output directory outside the source checkout. Neither preparation
nor verification launches a native process.

```sh
python3 -B tools/measure_hia_scalar_controller_controls.py prepare \
  --source /absolute/source \
  --expected-source EXACT_SOURCE_COMMIT \
  --native-binary /absolute/original/native/hia-ndu-bridge \
  --native-build-receipt /absolute/original/build/build-receipt.json \
  --native-provenance /absolute/original/provenance.json \
  --output /absolute/new/scalar-controls
```

Retain the reported plan digest before running. Supply that exact value:

```sh
python3 -B tools/measure_hia_scalar_controller_controls.py run \
  --directory /absolute/new/scalar-controls \
  --expected-plan-sha256 FROZEN_PLAN_SHA256
python3 -B tools/measure_hia_scalar_controller_controls.py verify \
  --directory /absolute/new/scalar-controls \
  --expected-plan-sha256 FROZEN_PLAN_SHA256 \
  --output /absolute/new/scalar-controls/VERIFICATION.json
```

The create-only `RUN-STARTED.json` prevents rerunning even an interrupted
campaign in the same directory. A later study must be a separately identified
plan with the preceding failure retained; it cannot silently replace it.

`verify` does not import Hepta execution modules or launch a native process.
It reconstructs each native request from the frozen pool with exact rational
Q32 conversion, checks the frontier/feasibility and tie outcome against the
original response, verifies stream and process receipts, checks every stored
object, and recomputes cost summaries from original cell records. It can verify
an honestly incomplete campaign; integrity verification is separate from
`MECHANISM_COMPLETE`.

The evidence contains `PLAN.json`, the create-only run marker, 128 scheduled
cell records, `SUMMARY.json`, and content-addressed source/native/request/reply
objects. The summary permanently reports
`incremental_decision_value_established=false`,
`stable_total_benefit_established=false` and
`economic_benefit_established=false`. No timing outcome automatically upgrades
those claims or closes the broader P2 value gate.

## Regression tests and CI

```sh
python3 -B -m unittest -v tests.test_hia_scalar_controller_controls
```

Unit tests use explicitly authored replies solely for adversarial evidence
checks. They reject a self-consistent changed native cost table, false frontier,
changed original stdout, unknown cleanup, promoted claims, corrupted objects,
duplicate JSON keys, modified plan pins and silent retrials. They also check
that failures retain cost and missing counterfactual costs remain unknown.
They are not native execution evidence.

`.github/workflows/hia-scalar-controller-controls.yml` runs those tests, builds
the original evaluator with locked dependencies, freezes and executes the
64-pair plan, independently verifies the evidence, and retains failures.
It leaves the historical paired native experiment and its original source
pin unchanged.
