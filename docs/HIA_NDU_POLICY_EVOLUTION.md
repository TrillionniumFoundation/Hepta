# Bounded policy learning with an original native NDU ablation

This experiment extends the existing dynamic-cache model and original NDU
adapter. It closes a runnable evidence path from a bounded learned search
policy to independently replayed native candidates. It does not establish
native application benefit, general NDU superiority, program safety, or
self-authorized deployment.

## Why this experiment is needed

The HIA graph `ndu-compact` arm calls
`hia_planning._compact_finite_actions` before native evaluation. That function
already performs exact Q32/resource DP and retains every required best path
per first action. In its unit-discount, common-terminal, zero-risk profile,
calling NDU afterward cannot improve the exact scalar ranking. Its cost must
still be paid. The prior negative observations must not be replaced with a
positive claim based on a different objective or an omitted oracle cost.

The existing `rust/hia-ndu-dynamic-model` experiment also has a genuine native
beam that does not call DP. This change reuses its model, resource arithmetic,
source-pin builder, sealed process transport, and original native NDU APIs.
Two new native modes accept supplied candidate paths:

- `supplied` independently reconstructs each complete path, enforces quota,
  epochs, and cost budget, and computes the scalar candidate ranking.
- `supplied_ndu` reconstructs **the same candidate set** and calls the unchanged
  `codex_hepta_ndu::evaluate_recursive_utility` and
  `codex_hepta_ndu::evaluate_candidates_with_policy` APIs.

Both modes reject empty or duplicate candidate inventories, incomplete paths,
out-of-range or over-quota resident masks, and over-budget paths. Neither mode
runs beam search, exact DP, or any workload command. Native search states and
transitions must both be zero. Python independently replays returned witnesses
and verifies that the path inventory was preserved exactly. Original native
source bytes remain pinned to the existing dynamic profile's
`8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d`.

## One model owner and a fixed search budget

`hepta/hia_ndu_policy.py` delegates legal actions, preparation, retirement,
invalidation, forecast cost, and quota accounting to
`hepta/hia_ndu_dynamic.py`. It changes only which resident states survive beam
pruning. Each policy sees the same model and the same full set of legal masks.
Approximate pruning is explicit; it is not described as a complete search.

The retained feature is forecast reuse savings before announced invalidation.
The fixed parameter grid varies lookahead and a nonnegative retention weight.
This is an ordinary empirical learner. It makes no LLM request and has no
unreported model training or weights. Width is fixed at two for the learned
arms. A selection evaluates no more than 4,096 transitions. Each learned arm
has the same two-million-transition training ceiling. Unused work is recorded
rather than padded. The complete candidate replays and input validation are
included in observed wall time; the transition counter counts search work,
not every Python instruction.

| Arm | Decision rule | Data use |
| --- | --- | --- |
| `fixed-direct` | Always use an empty resident set | No fitting |
| `greedy` | Width one, no retention feature | Current model only |
| `beam` | Width two, no retention feature | Current model only |
| `learned-value` | Empirical minimum across the frozen feature grid | Training tasks only |
| `evolved-policy` | Three rounds of adjacent parameter mutations | Training proposal, a fresh selection set per round |
| `exact` | Retain every legal resident state | Final model only; audited independently afterward |

All candidate generation, losing training candidates, validation generations,
final policies, exact controls, transport, native evaluation, and audit costs
remain visible. Exceeding a work ceiling raises an explicit refusal. A partial
search is never returned as a completed task.

## Restricted evolution and independent final evaluation

The protocol fixes 24 training seeds, three disjoint eight-task selection
sets, and 24 final seeds. A generation proposes a local parameter mutation
using training data. The independent selection gate requires a strict aggregate
modeled improvement, no individual-task modeled regression, and complete
resource-witness validation. Failed proposals remain in the report. The final
holdout cannot choose another proposal or alter a gate.

This is a bounded strategy-improvement experiment, not autonomous source
rewriting. Admission to the next research generation is separate from a
full-cost improvement claim. A parameter change with improved modeled costs
can still lose after search, verification, training, build, and maintenance
costs. Every result retains `authority=DENY_ALL`,
`production_activation=false`, and no safety certificate.

After final execution, the existing independent bottom-up implementation
checks exact scalar optima. It is not used to supply candidates to the learner
or to NDU. Every final policy must have nonnegative regret, and the complete
control must have zero regret. The original native ablation receives the beam,
ordinary learned, and evolved policy candidate sets in alternating control
order. Both raw responses and process frames are retained. Equality of
rankings is a legitimate negative NDU-quality result in this scalar profile.

## Real module cost input

The optional `--module-report` reads a successful same-source
`qualify_hia_stb_service.py --stage study` report. It requires all eight builds,
all four timing groups, the original per-batch samples, the same call count and
checksum across candidates, complete six-function VM/native observations,
no PGO evaluation leakage, unchanged source identity, and matching bytes of
every built image. The imported report and images are hashed at freeze and
checked again at execution.

Each imported task compares HIA with **one** of the seven registered
alternatives. This is a pairwise image-admission study; it does not quietly
choose the best alternative after seeing final measurements. Group zero
supplies training samples. Three disjoint windows from group one supply the
three generation gates. Groups two and three supply final samples. These are
independent timing samples of the same semantic corpus, not a claim of unseen
semantic workloads.

The actual measured `batch_ns` and `load_ns` populate forecast costs. All
build/PGO/preparation costs remain in the original study ledger and are
reported once. The model assumes already-built images, zero retirement cost,
and uses image file bytes as an accounting proxy. No observed unload cost,
physical RSS bound, or actual controlled module dispatch is invented. A new
native dispatch campaign is required before claiming module-level net benefit.
With a single optional image, width two already retains all resident states;
this narrower input may correctly leave no room for a learned policy or NDU
to improve the exact scalar decision.

## Reproduction

Build the current adapter from the exact pinned upstream object in a fresh
output directory:

```sh
python tools/build_hia_ndu_dynamic_bridge.py \
  --upstream /absolute/path/to/hepta-private-ci \
  --output /absolute/path/to/fresh-native-build \
  --cargo /absolute/path/to/rust-1.95.0/bin/cargo
```

The builder records exact source, adapter, lockfile, compiler, binary, command
output, and build cost. Do not substitute a historical binary. The supplied
modes require an adapter rebuilt from this source revision.

Commit the intended source before freezing. Freeze and run are separate,
exclusive-output operations; results never relax the source identity check.

```sh
python tools/qualify_hia_ndu_policy_evolution.py freeze \
  --native-binary /absolute/path/to/fresh-native-build/target/release/hia-ndu-bridge \
  --native-manifest /absolute/path/to/fresh-native-build/build-receipt.json \
  --output /absolute/path/to/registration.json
python tools/qualify_hia_ndu_policy_evolution.py run \
  --registration /absolute/path/to/registration.json \
  --output /absolute/path/to/new-campaign-directory
```

Add `--module-report /absolute/path/to/service-study/report.json` to `freeze`
for the actual module's measured-cost input. Register that campaign before
running the policy experiment; do not select the input study by its result.
Run formal timing serially with the service campaign. The shared host is not
claimed to be exclusive.

Tests:

```sh
python -m unittest tests.test_hia_ndu_policy tests.test_hia_ndu_dynamic
HEPTA_DYNAMIC_POLICY_BINARY=/absolute/path/to/fresh-native-build/target/release/hia-ndu-bridge \
HEPTA_DYNAMIC_POLICY_MANIFEST=/absolute/path/to/fresh-native-build/build-receipt.json \
python -m unittest tests.test_hia_ndu_policy.OriginalNduSuppliedPathTests
```

The unconfigured native test is an explicit skip, not native evidence. Preserve
`RESULT.json`, `LEARNED.json`, `EVOLUTION.json`, each generation/arm file,
`native-frames.jsonl`, registration, and both native/source-module build
receipts. The caller should also time the enclosing command, including final
serialization. Nested wall measurements must not be added to their enclosing
wall. Human review and long-term maintenance remain unknown unless actually
recorded. A completed finite-model campaign does not by itself meet the
system's native-benefit or RSI full-cost gate.
