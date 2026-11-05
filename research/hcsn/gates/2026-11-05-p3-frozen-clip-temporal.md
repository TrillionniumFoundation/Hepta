# P3/P4: frozen real CLIP temporal-fusion pilot, with negative controls

Evidence timestamp: 2026-11-05 UTC. Existing Draft PR #512, starting from
`10e699c16c1e2bf9cf6a0b9da9bdefe2be9a21b0` (the separately verified P2 content-hold
checkpoint). **Research only; P3, P4, P5 remain OPEN.**

## Result

The real pretrained-encoder path now executes. The experiment does **not**
establish a Call/Put mechanism advantage. On the aligned panel, every model
has the same 96.09375% visual and paired-label recall. A simple overwrite
baseline has better contradiction classification and lower local fusion cost.
Unknown-class rejection is inadequate: 57.8–65.9% of the two heldout classes
are still accepted at the measured ID acceptance levels below.

This pilot uses genuine images and genuine pretrained image/text encoders, but
**class-name text prompts and synthetically assembled sequences**. It is not a
natural-caption, audio/video, generative, or independently prospective benchmark.

## Exact data, model, and execution

| Item | Frozen identity / actual scope |
|---|---|
| CLIP source | `openai/CLIP`, `d05afc436d78f1c48dc0dbf8e5980a9d471f35f6` |
| Encoder | official ViT-B/32, 151,277,313 frozen parameters |
| Weight SHA-256 | `40d365715913c9da98579312b702a82c18be219cc2a73407c4526f58eba950af` |
| Data | `uoft-cs/cifar10`, revision `0b2714987fa478483af9968de7c934580d0bb9a2` |
| Train Parquet SHA-256 | `8428b53a88a11ac374111006708df51469e315a22ac6d66470afd9c78d2ae883` |
| Test Parquet SHA-256 | `841389e6f2d64f28bf17310e430aebac20ec3ba611a3c5e231dc93c645ce84de` |
| Frozen features SHA-256 | `1da822cc4265c96d0331662f1303c36a5d2ac9936f83b392d22e40f081bcb91e` |
| Feature extraction | 400 real images, 10 text prompts, one CPU thread, batch 4 |
| Runtime | Python 3.12.14, PyTorch 2.10.0+cpu; complete versions in execution receipt |

The original archive download was slow and was explicitly stopped through its
execution session (exit 130). The completed run uses the pinned Parquet mirror;
its full file lengths and SHA-256 digests were verified before decoding. Image
identities are **original row positions in that mirror**, not an asserted match
to the original Python archive's row order. The receipt explicitly records that
archive-order equivalence has not been independently checked.

For each class, take the first 16 train rows, the next 8 train rows for
calibration, and the first 16 test rows. This yields 160/80/160 encoded images.
All selected rows and RGB pixel SHA-256 values are recorded. No selected pixel
hash overlaps across those three splits. The largest unit-vector norm error
is 2.384e-7, and every embedding is finite.

The fusion learner uses only classes 0–7: **128 training images, 64 calibration
images, and 128 test images**. Classes 8/9 contribute **32 test images** to the
unknown-class panel. They are held out from this fusion learner, not proven
absent from CLIP pretraining. Encoding unused train/calibration rows for those
classes does not admit them to the fusion training or calibration streams.

The 512-dimensional frozen image/text embeddings are projected against the
eight known-class text prototypes and softmaxed using CLIP's recorded logit
scale. Thus this pilot deliberately studies a narrow eight-class temporal
interface. It does not test general semantic fusion of the full embeddings.

Primary source context:

- CLIP model and interface: <https://github.com/openai/CLIP>
- CIFAR dataset: <https://cave.cs.toronto.edu/kriz/cifar.html>
- Exact mirror: <https://huggingface.co/datasets/uoft-cs/cifar10/tree/0b2714987fa478483af9968de7c934580d0bb9a2>

## Task and controls

The model keeps the last observed visual and textual class-distribution
memories separately. It predicts the visual class with an identical fixed
decoder and classifies whether the last observed image/text labels match using
one learned contradiction head. **Visual recall does not use text to reconstruct
unobserved visual content.** Paired recall requires both last-observed labels
to be correct; it does not establish natural-language joint reasoning.

Four controls use the same frozen encoder outputs, generated training streams,
seed, optimizer, number of updates, and shared head initialization:

- Simplified stopping Call/Put features in the update gate.
- Put plus the normalized linear payoff, with the same number of gate weights.
- Ordinary sigmoid/tanh features in the update gate.
- Direct overwrite on each observed input, with no learned update gate.

The first three have **553 active trainable parameters**; overwrite has **545**.
All share the same 16-wide contradiction head. They are not FLOP-matched or
globally slope-matched. The Call/Put formulas are from the simplified stopping
kernel, not original coupled HX equity or an endogenous multimodal QVI.

For this gate, `C-P=v-1`. Mapping the readout weights from `[C,P]` to `[P,v-1]`
preserves the entire sequence output in the FP64 test. Independent Adam runs
need not agree because their parameter coordinates differ. The P1 report in
PR #513 gives the more extensive capacity and signed-Jacobian analysis.

Each of seeds **11, 23, 37** runs **120 Adam updates**, batch 24, length 12,
learning rate 0.01. Class and match losses are supervised; internal event
labels are not provided. Training intervals are all one unit. The irregular
interval panel is therefore time-distribution OOD, not evidence that a
continuous-time law was identified from diverse training intervals.

Each test scenario has 128 streams, length 24, and one final query per stream.
All modes and seeds use the **same** evaluation streams and source-image pool.
Three training seeds are not three independent image datasets or 384 unique
evaluation images. Several panels intentionally share events with changed
observation masks. Results below are exploratory paired descriptions, with no
population-significance or independent preregistration claim.

Missing observations hold the corresponding memory exactly for every model.
Each modality separately accumulates elapsed time until its next observation.
This fixes a discovered bug in the initial candidate: inserting a missing
frame previously changed the next update despite unchanged event times. The
fixed implementation gives identical outputs for a four-unit interval and a
three-unit missing interval followed by a one-unit interval. This does not
prove arbitrary resampling invariance of observed inputs.

## Quality results

Percentages below average the three paired training seeds.

| Final-query panel | Call/Put visual / paired recall | Put+linear | Ordinary | Overwrite |
|---|---:|---:|---:|---:|
| Aligned | 96.09375 / 96.09375 | 96.09375 / 96.09375 | 96.09375 / 96.09375 | 96.09375 / 96.09375 |
| Missing image in final half | 91.40625 / 91.40625 | 91.40625 / 91.40625 | 91.40625 / 91.40625 | 92.18750 / 92.18750 |
| Long blank final half | 91.40625 / 91.40625 | 91.40625 / 91.40625 | 91.40625 / 91.40625 | 92.18750 / 92.18750 |

The long-blank panel ends with 12 absent intervals of duration 32, i.e. 384
units without a new observation. Retention here comes from the shared mask
identity, not an exclusive analytic-neuron mechanism. The latest observed
target is carried through gaps; an unseen changed visual target is not inferred.

| Match/contradiction balanced accuracy | Call/Put | Put+linear | Ordinary | Overwrite |
|---|---:|---:|---:|---:|
| Aligned | 96.4209 | 96.8971 | 96.4209 | 99.5238 |
| One-frame text misalignment | 93.6543 | 93.1329 | 92.3754 | 98.2323 |
| Missing image | 99.1071 | 98.8095 | 98.9583 | 98.9583 |
| Missing text | 93.8988 | 93.6012 | 93.4524 | 99.2560 |
| Irregular time | 96.4209 | 96.8971 | 96.8971 | 99.5238 |
| Long blank | 97.0370 | 96.5984 | 96.5984 | 96.6667 |

The aligned panel contains 35 non-matches and 93 matches. Some conditions
have very small class supports (e.g. 16 matches in the missing-image panel).
The raw JSON preserves confusion matrices and per-class supports. Both classes
must exist to report balanced accuracy; a one-class panel returns null.
Small differences in these reused panels do not establish causal superiority.

### Unknown-class rejection remains a negative result

Choose each model's rejection threshold from the **5th percentile of ID-only
calibration confidence**, using 256 calibration streams. No unknown examples
or unknown labels tune the threshold.

| Model | Test ID acceptance | Heldout-class false acceptance |
|---|---:|---:|
| Call/Put | 97.65625% | 65.88542% |
| Put+linear | 97.65625% | 65.10417% |
| Ordinary | 97.65625% | 65.62500% |
| Overwrite | 96.09375% | 57.81250% |

The test operating points differ despite the common ID-only calibration rule.
The lower overwrite false-acceptance number is not a same-operating-point
claim. All four models fail to reliably reject the two heldout controller
classes; this is weaker than unknown-to-pretraining or open-world rejection.

## Measured cost and P4 limits

Actual frozen encoding of all 400 images and 10 prompts took **65.466 s wall /
65.069 s process CPU**, with peak process RSS **1,782,951,936 bytes**. Download
plus load took **34.489 s**. The encoding timer includes image preprocessing
and feature computation but excludes download/model loading and final NPZ
serialization. It is not per-request service p99. Peak RSS belongs to that
process and includes loading.

Fusion timings include both memories, both heads, mask/time logic, and input
validation, with already encoded inputs. Each measurement processes **32
streams × 24 frames**. Three warmups precede 30 measured repeats per trained
seed, giving 90 diagnostic measurements per mode.

| Model | Pooled batch wall median | Pooled batch wall p99 | Pooled batch CPU median |
|---|---:|---:|---:|
| Call/Put | 8.082 ms | 17.630 ms | 8.086 ms |
| Put+linear | 9.530 ms | 32.361 ms | 9.534 ms |
| Ordinary | 7.889 ms | 12.218 ms | 7.887 ms |
| Overwrite | 4.034 ms | 5.786 ms | 4.036 ms |

These are batch timings, not single-request p99. The shared host was also
running unrelated jobs; model order was fixed rather than randomized across
timing repeats. Ninety samples do not qualify a production tail. Fusion-process
peak RSS was **302,194,688 bytes**, an aggregate process maximum rather than
per-model isolated memory. CPU energy was not measurable from exposed hardware
counters, so joules remain null. The process is local; zero runtime network
communication is not a distributed-inference result.

Every variant consumes the same frozen encoder features and implements no
encoder skipping. Consequently **no saved encoder computation was demonstrated**.
The measured gate cost cannot be called a net saving. A complete quality-matched
end-to-end frontier, actual device energy, accelerator kernels and distributed
communication still require experiments. P4 remains OPEN.

## Verification and reproducibility

The new causal/data contracts passed **11/11 tests**. Coverage includes future
isolation, streaming equivalence, missing-payload irrelevance, exact blank hold,
independent batch behavior, matched active capacity/shared initialization,
heldout-class exclusion, consistent observed-history labels, domain rejection,
elapsed-time subdivision, absent metric classes, and the full-sequence
Call/Put-to-Put+linear weight mapping.

The combined existing retention + new retention + real-feature fusion suite
passed **28/28 tests**, zero skips. The unmodified scientific gate was actually
run and returned **exit 2**, with no production activation. This is consistent
with substantive scientific gaps, not merely a missing signature artifact.
An initial combined invocation omitted the legacy module search path and
reported 21 passed tests plus one import error. That failed log is retained;
the successful invocation supplies `PYTHONPATH=.:research/hcsn` to support the
unchanged upstream test's absolute import. No historical test was rewritten.

Quick replay uses the small committed frozen-input fixture, including its full
source/model/image-selection receipt:

```sh
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
export PYTHONPATH=.:research/hcsn
python -m unittest research.hcsn.test_p2_task_only_ctmc_retention research.hcsn.test_p2_content_hold research.hcsn.test_p3_frozen_temporal_fusion -v
python -m research.hcsn.p3_frozen_temporal_fusion \
  --features research/hcsn/fixtures/frozen_clip_cifar10_20261105.npz \
  --output /tmp/hcsn-frozen-clip-rerun.json
```

Regenerate embeddings from the exact pretrained source and public image data
with PyTorch 2.10.0+cpu, torchvision 0.25.0+cpu, pyarrow 23.0.1, ftfy, regex,
tqdm, numpy and Pillow installed. Pin the CLIP checkout to the source SHA above:

```sh
python -m research.hcsn.p3_frozen_clip_features \
  --clip-source /path/to/pinned/CLIP \
  --cache /path/to/asset-cache \
  --dataset-backend hf_parquet \
  --output /tmp/hcsn-regenerated-clip-features.npz
```

File paths must be new: the runners refuse to overwrite completed results.
The exact numerical replay and its source SHA-256 bindings are in the adjacent
execution receipt. Cross-platform timing or floating-point bytes may differ;
the committed fixture fixes the input actually used here.

## P0–P5 checkpoint and legacy gate mapping

This user-facing roadmap has six stages; existing source gates still use seven.
No old gate is renamed or silently accepted. New P3 covers the older separate
unimodal/multimodal stages; new P4 corresponds to old P5 efficiency; new P5 to
old P6 scaling.

| Requested stage | This session's concrete evidence | Remaining scientific requirement |
|---|---|---|
| P0 mathematics | #527 `5d91fac039437928cee1e3f68d9e9e5d22653633`: two numerical defects fixed; given-policy renewal independently separated from optimal fixed-reset QVI; 98 scoped tests | Original HX global admissibility, general state-dependent reset QVI, low-precision neural implementation |
| P1 attribution | #513 `9bfadcb94adee38406c842f17bc4d337033236a8`: Put+linear capacity identity, exact-source replay, ordinary baseline still better; 21 tests | Independent positive benefit beyond shape, optimizer coordinates, capacity and cost |
| P2 memory | #512 `10e699c16c1e2bf9cf6a0b9da9bdefe2be9a21b0`: long-hold recovery matches ordinary exponential memory; short writes/noise still fail; 17 scoped tests | Learned routing/event recognition, real Selective Copy/MQAR, noisy long-term memory and event-time learning |
| P3 real modalities | This frozen real image/text pilot and three-seed stress panels | Natural captions, broader independent data, missing-content inference, audio/video, robust unknown rejection |
| P4 efficiency | Whole feature extraction plus complete local fusion timings/RSS | Fixed-quality net saving, full online p99, real joules and communication, accelerators |
| P5 scale | No new backbone or generator training in this session | Preserve a demonstrated local benefit during encoder/backbone/generator scaling |

The three PRs have separate source lineages and are not a claim that a single
combined checkout passed every stage. They remain Draft and production-disabled.
