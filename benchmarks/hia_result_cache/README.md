# Actual HIA result reuse: finite pilot

The computational kernel is `kernel.hepta`. `lower_source` checks it into HIA
Core; the independent Core verifier admits it; the normal LLVM emitter and
Clang compile it into an x86-64 shared object. The executor identity-checks and
seals those exact ELF bytes before loading `calculate` through its scalar C ABI.
Every direct call and every cache preparation executes this function. HIA owns,
initializes, reads and drops its internal byte buffer. No C/Rust implementation
stands in for the HIA computation.

The four logical objects differ by seed and data epoch. Their cache entries
store `(ELF hash, n, seed, epoch, generation, value)` in fixed 64-byte slots.
There are two slots. Independent period-256 arithmetic checks native and reused
results, including non-period-aligned input sizes. Native refusal has the high
bit set, which cannot collide with a valid result in the registered domain.
Old epochs, wrong generations, changed code keys, corrupted values, missing
entries and quota overflow refuse before optional preparation is accepted.
Retirement zeros the slot. Closing an episode clears its payload arena. The
sealed ELF descriptor and loader mapping remain resident until process exit;
this does not claim dynamic library unload or persistent borrowed-buffer ABI.

## Comparison

The protocol is frozen in `PROTOCOL.json` before held-out execution. Seven arms
share the same executor, current state, announced queue, cache candidate grammar
and training-only cost estimates:

- direct HIA execution;
- a strong fixed cache set, selected over all eleven legal sets on independent
  training traces and then frozen;
- a local linear lightweight heuristic, with no IPC;
- the existing native light, exact-DP and beam planners;
- the same beam candidate construction plus original pinned NDU evaluation.

A training paired control feeds an identical model to beam and beam+NDU and
compares the entire candidate plans and selected action. The ordinary online
beam and NDU arms have separately calibrated decision costs, elapsed cost and
state; this one training control does not establish equality of their online
materialized candidates. The post-campaign matched-model audit instead replays
beam on every actually submitted NDU model, holding every model byte fixed,
and compares complete plans and the selected first action. Its separate wall
time belongs to campaign cost and never changes service timing or dispatch.
NDU is advisory and issues no execution or safety authority. Every actual exact-DP minimum is checked after
the campaign by the existing independent bottom-up finite-state audit. The
post-campaign audit cannot influence dispatch. Forecast optimality does not
imply measured elapsed-time optimality.

This is a distinct registered scalar result-cache workload. It does not replace
or relabel the earlier Rust-only matrix/transpose-cache workload. Positive or
negative results cannot be combined across those studies to close a claim.

## Running

Use a clean committed checkout with the full existing Hepta package. The native
planner build manifest must match the unchanged adapter source inventory and
original upstream commit; the process wrapper verifies both that inventory and
the exact sealed native binary digest. Build the existing planner with
`tools/build_hia_ndu_dynamic_bridge.py` if a qualified artifact is unavailable.

```sh
python -m unittest discover -s tests -p test_hia_result_cache.py -v
python tools/qualify_hia_result_cache.py \
  --output /absolute/new-output-directory \
  --clang /absolute/clang20/bin/clang \
  --planner /absolute/hia-ndu-bridge \
  --planner-manifest /absolute/build-receipt.json
```

The output directory must be absent and outside the frozen source checkout.
Existing evidence is never overwritten. Registration requires a clean complete
git status, including untracked files. HEAD, tree, source inventory, raw protocol,
planner/manifest, Python executable and Clang identities are observed before
work, before holdout, after audits and after process closure. Registration,
frozen training and kernel bytes are rechecked, and an observed mismatch cannot
be erased by a later return to the old bytes. These are trusted-host checkpoint
observations, not atomic custody or a transitive Python/libc dependency closure.
The runner writes registration before build/calibration and freezes all fitted
costs before held-out measurements. It retains generated Core and LLVM, build
captures, the artifact receipt, native planner frames, exact models/actions,
correct outputs, episode failures, offline audit and totals. It never retries a
timing failure. Nonzero exit or `completed:false` remains a failed campaign.

## Costs and limits

Episode wall time includes model construction, gate, native decision and
validation, mutations, HIA preparation, direct calls, reuse, output oracle,
cleanup and hot-path raw logging. Build/load, calibration, session startup/close,
qualification controls, offline audit and report work occur outside episodes
and are separately recorded. Nested timings must not be summed as disjoint
components. The campaign wall observation includes shared setup and audit.

`known_standalone_cost_ns` is a comparison allocation: each arm pays the full
HIA build/load/base calibration; native planner arms additionally pay the full
historical pinned bridge build and their own calibration/session cost. These
counterfactual totals are not additive across arms. Qualification-specific
controls and offline audit are reported in campaign cost rather than allocated
as runtime policy costs. Toolchain acquisition, human effort and energy are not
known, so these are explicitly known costs, not a complete lifecycle claim.

Payload occupancy is integrated at executor operation boundaries in byte-ns.
The 128-byte arena bound excludes Python metadata, mapped ELF and the HIA
kernel's transient buffer. Whole-process max RSS includes those resources but
is not a per-arm attribution. Allocation within the real HIA kernel remains
part of actual call wall time. The pilot has 84 episodes, 1,008 requests, three
registered queue patterns, two held-out sizes, and two repetitions. It has no
statistical power, isolation or generalization claim. `p1_closed` is always
false: actual invocation plus finite evidence is not sufficient for a general
NDU or language-speedup claim. No authority or production activation is granted.

## Auditing an already retained pilot

The original pilot must remain byte-for-byte unchanged. The standalone auditor
validates the original request/response frames and replays only the recorded
actual NDU models through beam, using the same pinned bridge binary/manifest:

```sh
python tools/audit_hia_result_cache_matched_models.py \
  --result /absolute/original-pilot/result.json \
  --registration /absolute/original-pilot/registration.json \
  --planner /absolute/hia-ndu-bridge \
  --planner-manifest /absolute/build-receipt.json \
  --output /absolute/new-audit-directory
```

Its audit wall time and the sum of original campaign plus audit work are
reported separately. This is an identical-model counterfactual check, not a
claim that independently calibrated online arms originally saw identical model
bytes. It cannot retroactively supply missing original full-git, protocol or
tool after-checks. The next unified run must use the strengthened runner on
its own frozen source checkout.
