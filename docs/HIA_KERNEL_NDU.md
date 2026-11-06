# Native NDU over complete HIA kernel image paths

This adapter is a separate protocol and build profile. It links unchanged
production Rust sources from hepta-private-ci commit
8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d. It calls three original entry points:

- PreferenceState::genesis and solve_preference_target create and update actual
  native preference states.
- evaluate_recursive_utility evaluates every supplied complete path.
- evaluate_candidates_with_policy applies native feasibility and Pareto rules.

It does not execute a kernel, generate measurements, authenticate a kernel
verification digest, or authorize publication. The experiment owner must
admit each full HIA image and each actual guest observation independently.

## Build and mechanism qualification

    python tools/build_hia_kernel_ndu_bridge.py \
      --upstream /path/to/pinned-private-ci-checkout \
      --output /path/to/new-isolated-kernel-ndu-build \
      --cargo /path/to/rust-1.95.0/bin/cargo

This uses the existing source-preserving isolated builder and committed lockfile.
Keep its output separate from all other bridge profiles. The package retains
the isolated builder's executable name hia-ndu-bridge; the new identity and
request schemas distinguish it.

    python tests/test_hia_kernel_ndu.py \
      --binary /path/to/new-isolated-kernel-ndu-build/target/release/hia-ndu-bridge \
      --output /path/to/new-mechanism-qualification

The qualification generates explicitly synthetic arithmetic fixtures, not
kernel performance data. It independently replays native preference values,
every returned iteration residual/revision, weighted terms, complete recursive
values, budget feasibility and the ordinary scalar frontier. It checks that
changing the actual native preference state changes image advice, chains the
returned state into a later generation, and rejects malformed inventories and
state digests. Passing these tests establishes mechanism behavior only.

## Wire entry points

The executable accepts one JSON request on stdin and returns one JSON response.
--identity returns its profile and upstream pin. --stream accepts bounded JSONL
frames, emits a hello, and adds stream_sequence to successful responses. At most
256 stream requests and 1 MiB per frame are accepted. No external commands are
available through either interface.

Request schema: hepta.hia.kernel-ndu.request.v1.

Required top-level fields:

| Field | Contract |
| --- | --- |
| objective_digest | SHA256 of the registered external objective |
| snapshot_digest | SHA256 of the current and past observation/model snapshot |
| action_registry_digest | SHA256 of canonical sorted-key compact JSON for images |
| generation | Positive, monotonically tracked experiment generation |
| horizon | 1 through 4 |
| utility_unit | Stable identifier of the registered scalar normalization |
| resource_unit | nanoseconds, microseconds, bytes, or modeled-work |
| resource_budget_q32 | Nonnegative signed-Q32 ceiling |
| risk_ceiling_q32 | Integer in [0, 2^32] |
| terminal_utility_q32 | Common delivery value in [0, 1000000 * 2^32] |
| preference | Exact preference record described below |
| images | Exactly three distinct O2/O3/Os backend image records |
| candidates | Every one of 3^horizon image paths, plus literal abstain |

An image record has id, backend, artifact_sha256 and verification_digest.
Identifiers and backend recipes must be unique. O2/O3/Os identify backend
optimization of the same retained full HIA program. Preserve target ABI,
frontend semantics, generated inputs, assembly and Kbuild postprocessing.
Do not change preprocessing macros when creating a backend-only variant.

Preference fields are mode ("fixed" or "dynamic"), previous_state (null or the
previous next_request_state), genesis_values, target and eta_q32. Each axis
record has axis and value_q32. A first request supplies genesis_values; a later
request supplies previous_state and an empty genesis_values array. Targets and
state must have the same one through sixteen axes. Each preference coordinate
lies in [-2^32, 2^32]. eta_q32 is registered as exactly 2^30 (one quarter).

Dynamic mode calls the original bounded damped solver toward the supplied
target. Fixed mode asks that same owner to validate the existing state against
itself and does not change its revision or values. The adapter returns the
initial and final raw values, all actual native iteration receipts, termination
receipt and a next_request_state. Native state-digest validation rejects
tampered prior states. The target rule belongs to the registered experiment:
the adapter neither learns it nor supplies it with future held-out outcomes.

The native solver validates bounded coordinates; it does not impose a
probability simplex or independently certify stability/conservation. The
returned solver receipts are local deterministic evidence. At each experiment
decision the current solved preference is held fixed over the bounded forecast
horizon; later real observations may produce the next native update.

A candidate has id, verified, verification_digest, support_digest,
resource_cost_q32, risk_q32, uncertainty_q32, and path. A non-abstain path has
exactly horizon phases. Each phase has image_id, event_digest, support_digest,
components, cost_q32 and discount_q32. Component records use axis/value_q32 and
have the exact state axes. Values are signed, registered utility contributions,
not unlabeled scores. The adapter computes each weighted term with the original
signed-Q32 nearest-ties-even multiplication, sums them, and subtracts cost_q32.
It then calls the original recursive evaluator on those actual computed values.

The input support digest must bind the real calibration/observation record and
forecast method. An input numeric forecast is not converted into an observed
future workload time. Every non-abstain path uses the request's common terminal
delivery value. Utility bounds are fixed at plus/minus one million units;
clipping, numeric overflow or unrepresented fields reject instead of being
silently normalized. Choose registered units that fit complete compilation,
switching and workload costs. Q32 microseconds cannot represent arbitrarily
long kernel build budgets.

Abstain has an empty path, verified=true, and exact zero resource/risk/uncertainty.
It represents doing no controller operation. It does not make mandatory
workload delivery free. The outer experiment must execute and charge its
registered incumbent continuation when the controller declines an update.

Successful response schema: hepta.hia.kernel-ndu.response.v1. It includes exact
request/objective/snapshot/registry bindings, the original entry-point names,
native state and iteration receipts, every weighted term and recursive value,
native rejected candidates, full Pareto frontier and evaluation digests.
selected_first_image_id is present only when the entire native frontier agrees
on one non-abstain first image. Ties across different first images produce null;
there is no unreported post-hoc winner selection.

## Eight-arm experiment interface

The action scope is a complete qualified HIA kernel image. A controller cannot
hot-swap arbitrary kernel translation units. A disposable guest may choose
another complete image at registered boot/workload boundaries; all real stop,
boot, warmup and state-transition costs belong in the ledger. Such a study is
adaptation between full-image workload batches, not an in-kernel livepatch
experiment.

Use the same retained HIA program and the same three qualified backend images
for all HIA controls:

| Arm | Selection rule |
| --- | --- |
| linux-stock | Frozen original Linux build and native algorithms |
| hia-static | Frozen HIA replay with the original backend recipe |
| hia-best-fixed | One complete backend image selected once on development data |
| hia-state-greedy | Current-stage external objective and real adoption cost |
| hia-ordinary-mpc | Registered ordinary finite-horizon planning objective |
| hia-same-objective | Independent ordinary calculation of the same native preference/utility objective and bounds |
| hia-fixed-preference-ndu | This native adapter with mode=fixed |
| hia-dynamic-ndu | This native adapter with mode=dynamic and actual returned state lineage |

Generate every 3^horizon image path independently of scores. Both NDU arms
therefore receive the same complete candidate permissions as ordinary controls.
The same-objective control should independently calculate the declared update
and recursion, rather than receiving NDU's output for free. If its ranking
equals NDU's, retain that result. Real native invocation and verification costs
can still distinguish the arms.

The existing dynamic-cache/raw-model adapters have cache residency and
direct/packed semantics. They are not reused as kernel policies. Likewise the
existing finite dynamic-frontier helper performs exact DP before its NDU call;
using its optimal path set cannot establish a new NDU search advantage.

Register development/calibration/holdout partitions, stationary/adaptive/
misleading-feedback regimes, objective units and targets, forecast inputs,
resource caps, path generation, tie handling and the complete arm/workload/
repeat matrix before measurements. Freeze candidate generation and selection rules
before holdout; controllers only receive current/past information and declared
forecasts. Preserve correctness failures and failed compilation variants in
the planned inventory. Performance conclusions need the registered actual
hardware/KVM environment; the existing Linux protocol permits TCG for boot
correctness, not for native performance qualification.
