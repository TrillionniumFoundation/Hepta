# Native raw-model planning integration, 2026-11-04

This change adds an explicit raw-model API beside the existing cost-model controller. Each call sends the complete bounded model to Rust. Rust performs the continuation search in both `exact_dp` and `ndu` modes. The latter additionally calls the unchanged original NDU evaluators after that shared search. Python performs typed admission and witness replay; it does not search a continuation or supply a precomputed winner to this API.

The default mode remains `exact_dp`. The original `AdvisoryController` and its request-local lazy witness optimization remain available and unchanged by this import. This change does not silently reroute that controller or the existing application benchmark through the new service.

## Source and behavior

`benchmarks/hia_raw_model/IMPORTED_SOURCE_20261104.json` records the exact copied blob identities from local source projection `311c4d67bad06ba9c7c49904a96c7154d57e0373`, tree `8c2073dc06289f1a49d7ee2b061ed7e166c244c6`. The projection's commit message mentions an abbreviated original commit; the projection and its copied bytes, rather than an unavailable original object, are the verified import identity. No historical result file or native executable is imported.

The minimal dependency set is the seven-file Rust adapter, two Python APIs, the generic builder extension and raw build wrapper, correctness and cost tools, their focused tests, and the fixed four-arm service protocol. Existing `hia_ndu_session.py`, `hia_ndu.py`, and `hia_native_differential.py` need no changes. The builder's original default adapter and debug profile stay unchanged; the raw wrapper explicitly selects the additional adapter and release build.

The original NDU pin remains `8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`. The raw adapter has its own protocol and executable identity. It cannot be passed as if it were the original supplied-candidate stream bridge. Source files, build receipt, sealed executable, request digest, generation and sequence are checked. Sessions are owned by their creating process and bounded to 256 requests, with explicit close and refusal behavior. They reuse transport and executable preparation, not an earlier model, plan, proof result or authority.

The domain remains at most four batches and two variants. The native search is finite and exact for that declared recurrence. Both modes use identical model inputs, candidate witnesses and scalar objective. Native receipts retain `DENY_ALL`, `safety_certificate=false` and `production_activation_allowed=false`. This service does not establish a program memory-safety proof or universal optimality.

## Fresh build and composition contract

Run these commands from a clean committed combined source tree. Use new output and target directories outside that tree. The shared original NDU checkout is read-only input.

```sh
RUSTUP_TOOLCHAIN=1.95.0 CARGO_NET_OFFLINE=true \
CARGO_TARGET_DIR=/absolute/new-native/target \
python3 -B tools/build_hia_raw_model_bridge.py \
  --upstream /absolute/pinned-8e52-checkout \
  --output /absolute/new-native/build \
  --cargo /absolute/cargo

python3 -B tools/qualify_hia_raw_model.py \
  --binary /absolute/new-native/target/release/hia-ndu-bridge \
  --build /absolute/new-native/build/build-receipt.json \
  --output /absolute/new-native/qualification --include-stream

python3 -B tools/measure_hia_raw_session_cost.py freeze \
  --binary /absolute/new-native/target/release/hia-ndu-bridge \
  --build /absolute/new-native/build/build-receipt.json \
  --output /absolute/new-native/service-cost

python3 -B tools/measure_hia_raw_session_cost.py run \
  --output /absolute/new-native/service-cost
```

The composition driver must bind its own expected source HEAD/tree and actual compiler identity. Require Rust 1.95.0 for this campaign, the exact upstream pin, matching complete adapter inventory, unchanged original Rust/non-manifest inputs, successful compiler command, retained original stdout/stderr hashes, a positive measured build cost, and the resulting executable hash. An inherited Rust 1.96 binary or old receipt cannot satisfy this new-build requirement.

Correctness admission requires 22 tests, zero failures/errors/skips, all 128 registered random-model IDs, the actual native transcript, unchanged inputs, and `status=passed`. The tests compare complete first-action frontiers with an independent exhaustive schedule oracle, exercise integer/domain rejection, stale identities, tampered replies, sequence bounds, child death, timeout, fork ownership and cleanup. The 318 one-shot calls historically seen are a useful consistency check; stream tests have separate counts and must not be misrepresented as part of that one-shot transcript.

The service campaign fixes 24 models, 31 rounds and 2,976 calls before execution. Admission requires all 744 four-arm decision quartets to match, zero errors/unattempted calls, all six registered session lifetimes, unchanged registered inputs and `measurement_complete=true`. A complete negative comparison is a valid measurement; a positive NDU advantage must never be inferred from completion alone.

## Cost scope and historical comparison

The four service arms are one-shot/session crossed with exact DP/original NDU. Each receives the same raw inputs and release image. Outer clocks cover complete API calls, startup and close; the common observed build is charged once to each standalone alternative. The protocol retains failures and gives no complete totals for an incomplete campaign. It runs no selected application, and it excludes imports, caller audit/logging, and preparation outside the recorded build. Record those separately in the enclosing composition instead of inventing zero costs.

The existing independent historical campaign is retained at `/home/qian-qi/work/hia-raw-session-cost-20261103-r1/RESULT.json`, SHA-256 `eff63812abea381a821e699b3a171fe4e8b44968bd1654a276f0a3d359bd1666`. It used the original Rust 1.96.0 release image, SHA-256 `94dbc97fecc8c40d5dd4732ea847ce3cbd9d3a042920be7d0f1be53ef811e2ef`, and is not evidence of a new Rust 1.95.0 run.

| Historical arm | Complete service seconds, excluding common build |
| --- | ---: |
| one-shot exact DP | 11.440734764 |
| one-shot NDU | 11.766275812 |
| session exact DP | 5.843330610 |
| session NDU | 6.066349753 |

All historical decisions and witnesses matched. NDU cost 2.8455% more with one-shot transport and 3.8166% more with sessions. Reusing processes reduced the service cost in both modes; that shared improvement is not an incremental NDU decision benefit. The historical common build was 20.155671609 seconds, charged in full to each arm.

## Remaining comparison boundaries

This native service removes the old Python-search-then-native-ranking structure from the new API, but both native modes still share the same exact recurrence. NDU has no richer information or action set in this scalar bounded model. Lower transport overhead cannot establish a planning-quality advantage over the same-information exact DP.

The service study has no strong-fixed or lightweight application arm. The existing four-arm application qualification remains the separate place to compare those controllers, including program execution, preparation/proofs, residency, invalidation, startup and cleanup. Declared future decision costs are identical model inputs here; they are not measured future per-mode latency. A full application comparison must additionally account for compiler/dependency preparation, selected-program work, errors and all lifecycle costs, under the same information budget. The import and its correctness tests do not close that application-level net-benefit question.
