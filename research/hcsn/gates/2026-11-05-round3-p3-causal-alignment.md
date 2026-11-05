# Round 3: causal cross-modal source matching, with an unchanged negative attribution result

**Actual frozen-image/text execution is complete. The new path jointly consumes
query text and observed visual memory. It does not establish an HCSN-specific
quality advantage; P3/P4 scientific acceptance and production activation remain open/false.**

The protocol was published before execution at
[`cd71547cb5129985950576311bac37fa73c38aa2`](https://github.com/TrillionniumFoundation/Hepta/commit/cd71547cb5129985950576311bac37fa73c38aa2),
on exact #512 base `cad9fa2dedee8d13061282e19f59980bf215b703`.
Protocol SHA256 is `229649c36578813d5bca384266b8a1b60649c81a7e67b8d4abbecc23544776b7`.
This freezes the new task and budget, but the underlying image subset had
already been evaluated in round 2. It is exploratory reuse, not an untouched
external holdout or an externally registered trial.

## What was implemented and trained

The exact official frozen CLIP ViT-B/32 features from round 2 are reused:
151,277,313 encoder parameters, feature file SHA256
`26d2501a6c0d0c7204f49dc3249287118de807220f53e38f5e9f81f7f1b1719c`.
The original-image-disjoint COCO/SugarCrepe splits contain 112 training,
56 calibration, and 112 test caption rows. The test rows refer to **97 original
images**. No encoder weights are updated or downloaded for this round.

At each time the actual elapsed interval advances, an observed image enters
a four-slot FIFO, and then an observed positive text queries the current FIFO.
Every scorer receives the same observed tensors, masks, memory policy and
physical times. The FIFO does not inspect source IDs, parse truth, deduplicate
equal source IDs, or select a write according to a target. Multiple observed
copies of the correct source remain multiple valid answers; the loss sums
their probability mass. Missing text is unscored. NONE means that the source
image of the current text is absent from the bounded observed FIFO.

Both image and text enter pair features: eight group product sums, eight group
squared distances, and log1p(slot age). A shared 16-wide scorer adds a learned
residual to 20 times full embedding cosine. Call/Put and a boundary-value/
signed-slope-matched ordinary sigmoid control have **322 trainable parameters**,
identical initialization tensors and paired streams. Ordinary is locally
tangent-matched, not globally function- or FLOP-matched. Mapped Put+linear
is evaluated from each trained Call/Put; it is not an additional fitted winner.
Raw cosine and time-only-newest have zero learned parameters.

Seeds 101, 113 and 127 each train Call/Put and ordinary for exactly 240 Adam
updates, batch 16, length 8, learning rate .003, gradient clipping at norm 5.
Training combines marginal source-slot/NONE likelihood and a quarter-weighted
source-image positive-versus-edited-caption ranking loss. All training data
come from the training split. All final checkpoints, 240-step losses and
gradient norms, per-row decisions and calibration margins are retained.

SugarCrepe negatives only compare with **their own source image** in the
separate ranking task. An edited caption is never assumed false of every
other image in the FIFO. Source identity matching and semantic contradiction
are different targets.

## Actual results

Each panel reports one final observed positive-caption query for each of the
112 test rows. Source-present panels score correct matches including rejects;
source-absent panels score erroneous accepted matches. These are means of the
three fixed seeds, reusing the same data. Mapped Put+linear has the same
decisions as Call/Put in every recorded row.

| Panel / metric | Call/Put | Ordinary tangent | Raw cosine | Time-only newest |
|---|---:|---:|---:|---:|
| Aligned: correct source match | 98.512% | 98.512% | 99.107% | 100.000% |
| Delayed text: correct source match | 99.107% | 99.107% | 99.107% | 0.000% |
| Text gap: correct source match | 99.107% | 99.107% | 99.107% | 0.000% |
| Irregular time: correct source match | 98.214% | 97.619% | 99.107% | 100.000% |
| Long blank: correct source match | 100.000% | 100.000% | 99.107% | 0.000% |
| Missing source frame: false accepted match, lower is better | 2.976% | 2.679% | 3.571% | 100.000% |
| Evicted source: false accepted match, lower is better | 2.976% | 2.679% | 3.571% | 100.000% |
| Given-source positive/edited caption ranking | 72.917% | 72.619% | 73.214% | 50.000% |

The absent-source counts per seed are Call/Put **4, 3, 3 out of 112**,
ordinary **3, 3, 3**, and cosine **4, 4, 4**. The absent-frame and eviction
panels end with the same candidate-buffer contract, so their equal results
are not two independent rejection demonstrations.

Thresholds are the lower empirical 5th percentile of top-slot-minus-NONE
scores on **332 calibration source-present queries**. Actual calibration
acceptance is 95.1807% for the learned controls and time-only, 95.4819% for
cosine because of ties. All thresholds are fixed before test scoring. Test
acceptance is separately reported in the raw data; the methods are not
asserted to have exactly equal test operating points. The 332 queries reuse
47 calibration images and are not 332 independent image samples.

There is no consistent Call/Put advantage. Its largest observed positive
source-matching difference from ordinary is **0.5952 percentage point** in the
irregular panel; its two absent-source rates are each **0.2976 point worse**.
Paired image-cluster bootstrap intervals retain all captions and all three
seeds per sampled original image. They are descriptive on this already used
subset, not external population significance.

The prespecified uniform +2-point superiority criterion fails. Moreover,
ordinary aligned accuracy is already 98.21–99.11% across these seeds, so the
criterion runs into a ceiling in that panel. It must not be converted into
a theorem against all free-boundary mechanisms. The near-equality of the
actual paired rows and the strong smaller cosine control are the relevant
bounded empirical observations.

## What the new cross-modal path establishes, and its limits

Unlike the separate modality-memory updates in round 2, the scorer directly
conditions on both the query and each historical visual embedding. Reversing
the final text queries changes the chosen visual slot on 85–87 of 112 rows
for the learned scorers in seed 101, but zero for the time-only control.
The perturbation is reported as an input-dependence diagnostic; accuracy is
not calculated against the old, now-inapplicable query targets.

The delayed panel uses lags 1–3 and defeats the newest-only shortcut. This
is useful causal content-matching integration. However:

- The four random candidate images are easy: raw cosine already obtains
  approximately 99.1% delayed-source recall. Harder semantically similar
  distractors and genuinely unused images remain necessary.
- The task is **text-query-to-visual-FIFO source retrieval**. Text has no
  recurrent state. Text gaps therefore do not establish recovery of a lost
  text memory or bidirectional temporal fusion.
- The irregular panel inserts the true image in the final step, so its age
  is zero. It varies distractor ages, not irregular delays of an old target.
- The long-blank success uses a shared exact FIFO retention mechanism.
  It does not show autonomous learned event timing or a special HCSN memory.
- NONE means absent source provenance. A different image can still be
  semantically compatible; this is not novel-class rejection or a universal
  contradiction label.
- Images and captions are real, while their order, masks and intervals are
  constructed. No natural audio/video alignment claim is made.

## A review defect was repaired and its first attempt retained

Independent source review found that the first decision adapter read the
evaluation `slot_ids` to decide whether any slot was occupied. Those IDs were
correct in the experiment, but they did not belong in an inference decision.
The corrected adapter uses the model's observation-only FIFO validity;
all-step decisions derive occupancy from observed-image counts. Invalid slots
are explicitly masked before choosing a candidate.

The first execution's complete source, tests, manifest, log and compressed
raw result are retained in `2026-11-05-round3-p3-attempt1/`. The corrected
six-condition campaign was run again without changing data, protocol,
hyperparameters or checkpoint selection. All six **240-step loss/gradient-norm
traces**, all final parameter tensors, and all 15 seed/control records of
calibration, panel decisions and pair rankings are exactly identical. There
are no intermediate parameter snapshots, so per-step parameter identity is
not claimed. Timing is excluded from this identity check.

Thus there are **six unique trained conditions and twelve actual fit
executions including the repair replay**, not twelve independent experiments.
The source and raw-result hashes distinguish the two executions.

## Verification and cost

The corrected **11 scoped tests** pass: causal prefix/chunk execution,
unobserved-payload and label independence, multi-positive mass and FIFO
eviction, whole-function and input-gradient mapping, physical blank subdivision,
split/panel contracts, missing queries/empty buffers, joint input dependence,
observation-only decision adaptation, invalid inputs and real query-loss training.

An independent queue implementation (not `source_targets`) reconstructed every
memory, age and target and reloaded the actual trained weights. It verified
**105 model/panel combinations**, all raw decisions, integer denominators and
scores, **15 exact calibration replays**, **15 slot-permutation checks**, and
**15 metadata-tampering independence checks**. It also verified the paired
322-parameter initialization and retained multiple positive slots.
These checks establish source/implementation consistency, not external
scientific acceptance.

Cost review found one further comparator defect: ordinary tangent originally
computed the analytic put and then replaced that unused tensor with its sigmoid
control. The unused work inflated the ordinary baseline. It has been removed;
the published pre-repair source is retained at `d431b0b1...` and the original
timing samples remain in the raw result. No model is retrained or selected.
At all six trained checkpoints and seven panels, **42 complete outputs/states
are elementwise exactly equal**. Six additional comparisons show exact equality
of gradients for every parameter and both embedding inputs. These comparisons
use `torch.equal`; the raw receipt's historical `bitwise_equal` field names do
not assert byte equality of signed zeros.

New randomized interleaved measurements compare the corrected controls and
the old ordinary implementation on the same fixed tensors and weights. They
include the complete FIFO, scorer and input validation, B=8, T=12, **80 repeats
per mode per seed**. Pooled medians over 240 samples on a shared one-thread CPU:

| Mode | Full feature-to-answer forward median |
|---|---:|
| Call/Put | 3.4676 ms |
| Mapped Put+linear | 3.4711 ms |
| Ordinary tangent, unused work removed | 3.2355 ms |
| Ordinary prior implementation, same interleaved run | 3.6581 ms |
| Raw cosine | 1.9455 ms |
| Time-only newest | 1.8963 ms |

These timings exclude encoding, process startup and network communication;
qualities differ. Ordinary is cheaper than Call/Put after removing the unused
work in this run; the original cost comparison is superseded. These timings
establish no fixed-quality full-system speedup. Actual
device energy and distributed communication remain unmeasured. Corrected-run
peak process RSS was **365,355,008 bytes**. The two campaign bodies total
**52.5111 wall / 51.4758 CPU seconds**; these counters start inside `execute()`
and end before JSON serialization, so interpreter/import/serialization cost is
not presented as included. First-attempt cost is retained, not discarded.

## Reproduce

```sh
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
python -m unittest research.hcsn.test_p3_causal_alignment -v
python -m research.hcsn.p3_causal_alignment_evidence --output /tmp/fresh-alignment.json
python research/hcsn/audit_p3_alignment.py --root . \
  --evidence research/hcsn/gates/2026-11-05-round3-p3-causal-alignment-raw-v2.json.gz \
  --output /tmp/fresh-alignment-audit.json
python -m research.hcsn.p3_baseline_cost_audit --output /tmp/fresh-cost-correction.json
```

The public raw JSON is losslessly gzip-compressed. Its uncompressed SHA256 is
`4bf3f82382f8735605371bb91da5fa34bddf156f66c8d3aa8f524c2b5613f369`.
The runner refuses to overwrite an existing result. The audit accepts JSON or
gzip and also requires a new output path. Original-image/feature identities,
all trained weights, traces, calibration margins, complete query results,
timing samples and bootstrap seeds remain reproducible from the committed
fixture and source.
