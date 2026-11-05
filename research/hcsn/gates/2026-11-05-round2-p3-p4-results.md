# Round 2: natural captions, calibrated unknown rejection, and complete online CPU cost

Research only. **P3/P4 scientific acceptance and production activation remain open/disabled.**
The newer six-stage user roadmap calls real modalities P3 and efficiency P4;
the existing seven-stage independent gate retains its original names. Nothing
in this report renames, weakens, signs, or bypasses that gate.

## Decisions supported by the executed evidence

1. Preserving absolute encoder similarity materially improves this new-image
   rejection test. At exactly 243/256 = **94.921875%** empirical test-ID coverage,
   maximum-softmax accepts **44/64 unknown images (68.75%)**, while maximum
   raw text-prototype cosine accepts **17/64 (26.5625%)**. These matched-coverage
   numbers are retrospective ROC diagnostics, not deployable thresholds.
2. Call/Put adds no demonstrated advantage on the natural-caption memory
   experiment. Its aligned joint entity recall is **83.63095%**, ordinary
   gating **83.92857%**, and direct overwrite **88.39286%**. All three obtain
   **73.21429%** aligned hard-negative caption accuracy.
3. A complete local online workload shows actual compute saving from exact
   input reuse. Identical Call/Put model traces take **30.21922 s without
   caching versus 4.20939 s with caching**, a **7.1790x** online wall-time ratio.
   This saving is attributable to ordinary caching, not a free-boundary policy.
4. The Call/Put to Put+linear identity survives full causal embedding-memory
   execution: maximum state discrepancy **5.9604645e-8** across the six panels
   and three trained seeds. Separate online score/final-state discrepancies
   are **2.9802322e-8**. No additional nonlinear capacity is established.

## Source and execution provenance

The protocol was committed **before new evaluation** as
[`d54ee89fb93a685716bac5a5ab5b66096444d1e5`](https://github.com/TrillionniumFoundation/Hepta/commit/d54ee89fb93a685716bac5a5ab5b66096444d1e5),
parent `8e352b84a1286836d156a281e28956d07a60157e`.
This is a public protocol checkpoint, not an independent evaluator attestation.

| Item | Identity |
| --- | --- |
| Protocol SHA-256 | `27bd587fa8efef7b2b124f72db05010ce0a3a9fc889b77a271fe5fa6bdac29f3` |
| Official OpenAI CLIP source | `d05afc436d78f1c48dc0dbf8e5980a9d471f35f6` |
| Official ViT-B/32 weight SHA-256 | `40d365715913c9da98579312b702a82c18be219cc2a73407c4526f58eba950af` |
| SugarCrepe source | `RAIVNLab/sugar-crepe`, `0047054b243992f0fad63d6f64f7544862daf846` |
| New frozen feature NPZ SHA-256 | `26d2501a6c0d0c7204f49dc3249287118de807220f53e38f5e9f81f7f1b1719c` |
| CIFAR mirror | `uoft-cs/cifar10`, revision `0b2714987fa478483af9968de7c934580d0bb9a2` |

CLIP has 151,277,313 frozen parameters; no encoder weights are updated. The
runtime is actual PyTorch 2.10.0+cpu, one thread. The receipt includes source
annotation digests, selected row IDs, raw image byte and decoded-pixel hashes,
captions, labels, image geometry, and encoder timing. Both external checkouts
were required to be clean and at their pinned commits. All requested images
were retrieved; failed downloads were not replaced by easier samples.

The complete new fixture is
[`frozen_round2_20261105.npz`](../fixtures/frozen_round2_20261105.npz), with its
[`source receipt`](../fixtures/frozen_round2_20261105.json). Raw assets and
weights are reproducible external inputs, not committed binaries.

Primary references:

- [Official CLIP implementation](https://github.com/openai/CLIP) and
  [CLIP paper](https://arxiv.org/abs/2103.00020).
- [Official SugarCrepe implementation/data](https://github.com/RAIVNLab/sugar-crepe)
  and [SugarCrepe paper](https://arxiv.org/abs/2306.14610).
- [COCO source](https://cocodataset.org/#download) and
  [caption collection paper](https://arxiv.org/abs/1504.00325).

### What is real and what is constructed

The images are actual COCO validation images; positive captions and seven
types of hard negatives come from the pinned SugarCrepe records. The temporal
order, observation masks, elapsed times, and missing-frame episodes are
constructed. This is a custom image-disjoint subset, not the official full
SugarCrepe benchmark and not a natural video dataset.

Splitting hashes the **original image filename**, so different caption types
for the same image cannot cross train/calibration/test. Within each type and
split, a predeclared hash order selects 16 train, 8 calibration and 16 test rows.

| Split | Caption rows | Unique original images |
| --- | ---: | ---: |
| Train | 112 | 109 |
| Calibration | 56 | 47 |
| Test | 112 | 97 |
| Total | 280 | 253 |

Decoded image hashes are also disjoint across these splits. The natural-caption
calibration pool is retained without training or model selection. Three model
seeds reuse the same test panels; 112 rows and three seeds are **not** 336
independent images. There is no assertion that these examples were absent
from CLIP's undisclosed pretraining data.

## P3A: preserve the information needed for unknown-input rejection

The old eight-class softmax representation discards common offsets:
`softmax(z + c) = softmax(z)`. A maximum-softmax rejection score consequently
cannot retain all absolute evidence that an input matches the known prototypes.
The new test explicitly retains the frozen normalized embeddings and compares
four predeclared scores: maximum softmax, maximum raw prototype cosine,
nearest known training image, and nearest known class centroid. All four are
reported, with no test-driven parameter search.

Training uses the existing 128 known-class round1 training images. New
calibration uses the next 16 training rows per known class after the first
24 rows already used in round1: **128 calibration images**. New test uses
the next 32 test rows per each of 10 classes after the first 16 used in
round1: **256 known and 64 unknown test images**. All new source row IDs and
decoded pixels are disjoint from round1. The known/unknown taxonomy remains
the same: classes 0–7 known, ship/truck held out from fusion. This is new-image
evidence in the same taxonomy, not novel unknown categories.

### Independently calibrated operating points

Each score threshold is its ID-only calibration sample's lower empirical
5th percentile. Unknown images and test ID images do not set these thresholds.
Actual test coverage is reported rather than assumed to equal 95%.

| Score | Known accepted / 256 | Known acceptance | Unknown accepted / 64 | Unknown false acceptance |
| --- | ---: | ---: | ---: | ---: |
| Maximum softmax | 252 | 98.4375% | 50 | 78.1250% |
| Maximum raw text cosine | 245 | 95.7031% | 18 | 28.1250% |
| Nearest known training image | 240 | 93.7500% | 16 | 25.0000% |
| Nearest known class centroid | 243 | 94.9219% | 22 | 34.3750% |

For example, the raw-cosine unknown rate's descriptive Wilson 95% interval
is **18.59%–40.13%** for 18/64. This finite class-balanced sample does not
establish a universal OOD guarantee. Nearest-image's lower unknown rate occurs
at lower ID coverage and cannot by itself establish a better operating point.

### Same-coverage diagnostic

The additional ROC diagnostic chooses a threshold from **test ID scores** to
accept exactly 243/256 ID examples. Cutoff ties would use a declared fractional
acceptance probability; these actual data have no fractional cutoff needed.
Unknown scores do not choose the cutoff. The diagnostic is labelled
`deployable_threshold: false` in every raw result.

| Score | ID coverage | Unknown false acceptance | ID-vs-unknown AUROC |
| --- | ---: | ---: | ---: |
| Maximum softmax | 94.9219% | 68.7500% | 0.76129 |
| Maximum raw text cosine | 94.9219% | 26.5625% | 0.95660 |
| Nearest known training image | 94.9219% | 31.2500% | 0.95569 |
| Nearest known class centroid | 94.9219% | 31.2500% | 0.95850 |

The score improvement is a useful engineering result. It belongs to the shared
frozen encoder and rejection readout; it does not establish a Call/Put-specific
memory benefit. A production threshold must come from independent calibration,
not the retrospective diagnostic. Broader unknown categories and their error
budgets still require new evidence.

## P3B: full-embedding causal memory on natural captions

Only the eight-parameter temporal gate is trained. Every learned variant has
the same inputs, state size, mask handling, 120 Adam updates, batch 16, training
length 8, learning rate .01, and seeds 61/73/89. Call/Put and ordinary runs use
paired initial parameters and streams. Put+linear maps the trained Call/Put
weights; it is not an additional independently trained winner. Direct overwrite
has zero trainable gate parameters and is reported as a smaller control.

The gate receives four continuous statistics of the current embedding,
memory, and elapsed time. Image IDs, caption correctness, split labels, targets,
and future observations never enter forward execution. Supervision asks memory
to retain the most recent **observed** image/text embeddings. First observations
initialize state and absent observations preserve state in every variant.
Consequently blank retention is a shared architectural property.

The two modalities update their memories separately and share only the gate
parameters. Neither update receives the other modality's state. Joint recall
is the conjunction of two retrieval successes. These experiments therefore
test temporal memory and bidirectional cross-modal retrieval, not learned
interaction between the modalities.

### Metrics and their exact meanings

- Image-to-caption entity recall: rank test positive captions from visual
  memory; any caption of the same original image is a correct entity.
- Caption-to-image entity recall: rank unique test images from text memory.
- Joint recall: both of those last-observed entities must be recovered.
- Hard-negative accuracy: use **visual memory only**, compare its similarity
  to the corresponding positive and negative caption. Text memory does not
  enter this readout. This measures the specified image/caption discrimination
  task, not a learned two-state contradiction detector.
- Text misalignment: each modality is scored against its own last observation.
  This measures separate memory retention under offset streams. It does not
  demonstrate recovery of a latent real-time correspondence.

### Joint entity recall, mean over three paired model seeds

| Panel | Call/Put | Mapped Put+linear | Ordinary | Overwrite |
| --- | ---: | ---: | ---: | ---: |
| Aligned | 83.6310% | 83.6310% | 83.9286% | 88.3929% |
| Missing image | 85.1190% | 85.1190% | 84.8214% | 88.3929% |
| Missing text | 83.3333% | 83.3333% | 83.9286% | 88.3929% |
| Offset text | 83.3333% | 83.3333% | 83.6310% | 85.7143% |
| Irregular time | 82.1429% | 82.1429% | 82.1429% | 88.3929% |
| Long blank | 84.5238% | 84.5238% | 84.2262% | 88.3929% |

Aligned hard-negative accuracy is 73.2143% for all four variants. Per-type and
per-row scores, retrieval decisions, and all seeds are retained in the raw JSON.
Small differences on other panels do not establish a reliable mechanism gain.
The test contains 97 source images, and there is no seed-independent advantage
over the smaller overwrite control.

Complete feature-to-output fusion timing used randomized interleaving,
60 repeats per mode per seed, B=8 and T=12. Pooled medians over 180 samples are
Call/Put **6.1471 ms**, mapped Put+linear **6.3313 ms**, ordinary **4.2954 ms**,
overwrite **1.9109 ms**. Shared-host tail observations are noisy and are not
production latency qualifications. These fusion-only timings exclude encoding;
the next experiment includes the actual encoder path.

## P4: actual online encoder, control, output, and cache costs

Four cases run in fresh processes using the same source images and trained
seed-61 Call/Put checkpoint. The fixed request sequence cycles the first eight
lexicographically ordered test-image filenames for 64 requests. All eight are
real COCO images; the repetition pattern is constructed, not natural video.

The measured request includes local raw-file reads, cryptographic input keys,
image decode and preprocessing on cache misses, actual CLIP image/text encoders,
the recurrent controller, positive/negative caption scores, and output trace
serialization. The cache key includes encoder source/weights/preprocessing
namespace and exact image bytes or text. Unknown future inputs cannot hit it.
Caching no-ops only exact previously encoded inputs; it does not use labels.

| Case | Image encoder calls | Text encoder calls | Online wall s | CPU s | Median request ms | p99 request ms | Isolated peak RSS bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Call/Put, uncached | 64 | 128 | 30.21922 | 29.94912 | 423.6237 | 890.4567 | 1,751,646,208 |
| Call/Put, cached | 8 | 16 | 4.20939 | 4.19579 | 0.7668 | 760.4391 | 1,751,519,232 |
| Mapped Put+linear, cached | 8 | 16 | 4.10832 | 4.04589 | 0.5575 | 773.7064 | 1,752,502,272 |
| Overwrite, cached | 8 | 16 | 4.01990 | 3.98591 | 0.3312 | 696.4873 | 1,752,412,160 |

The uncached/cached Call/Put **full state-and-score trace digests are identical**.
All four encoded-input traces are identical. The hard-negative accuracy is 75%
for each case on these eight repeated examples. The cache reduces image calls
by 56 and text calls by 112, with all hashing/controller costs included.

The online wall speedup is 7.1790x and CPU time ratio is 0.14010. Including
Python startup, weight verification/loading, setup, warmup and the full worker
process reduces the wall ratio to **41.0008 / 15.7050 = 2.6107x**. Setup and
warmup are separately recorded. Cached inference does not meaningfully reduce
the encoder-dominated process RSS here.

This result closes the narrow engineering question of whether an actual exact
reuse path can save more CPU work than its control overhead on this repeat-heavy
load. It does **not** establish that the HCSN controller discovers beneficial
skips, that savings persist at another repetition rate, or that cached HCSN beats
ordinary caching. The overwrite control is cheaper on this small load. Other shared tasks and
reproducible build-cache cleanup caused resource contention during this session. p99 uses
64 requests per case, fixed case order, filesystem cache and shared-host load;
it is a descriptive measurement only.

No hardware energy counters were available and CUDA was unavailable. Joules
remain `null`; CPU seconds are not converted into energy. Measured code makes
zero runtime network calls, but distributed communication was not measured.
Actual target-accelerator kernels, real device energy, sustained production
tails and distributed costs remain open.

## Verification and reproducibility

The final eight focused semantic tests cover causal prefix invariance, exclusion
of targets from forward execution, absent-payload irrelevance, original-image
split identity, tied-score rejection accounting, every last-observed scenario,
the complete mapped memory trajectory, invalid-domain rejection, and equivalence
of the online streaming adapter to full sequence execution (some tests cover
multiple related checks). Initial seven-test and final eight-test logs are kept.

An additional read-only audit verifies source/feature hashes, CIFAR row labels
and indices against receipts, cross-round source/pixel separation, natural
caption correspondence to the pinned annotations, raw decision denominators,
calibration versus test-ID diagnostics, and exact cached online output identity.
Passing it means artifact consistency, **not scientific acceptance**.
Another agent independently inspected the input and metric paths and checked
the actual CIFAR arrays against receipts. That is computational cross-review,
not an external evaluator signature.

```bash
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
export PYTHONPATH=.:research/hcsn
python -m unittest research.hcsn.test_p3_round2_study -v

# Clone and check out the exact CLIP and SugarCrepe commits above first.
# Existing outputs are never overwritten: use a fresh output path.
python research/hcsn/p3_round2_features.py \
  --clip-source /path/to/CLIP --data-source /path/to/sugar-crepe \
  --cache /path/to/asset-cache --output /path/to/new-features.npz \
  --protocol research/hcsn/gates/2026-11-05-round2-p3-p4-protocol.json

python research/hcsn/audit_round2_multimodal.py \
  --data-source /path/to/sugar-crepe --output /path/to/fresh-audit.json

python research/hcsn/p3_round2_study.py \
  --features research/hcsn/fixtures/frozen_round2_20261105.npz \
  --prior-features research/hcsn/fixtures/frozen_clip_cifar10_20261105.npz \
  --protocol research/hcsn/gates/2026-11-05-round2-p3-p4-protocol.json \
  --output /path/to/fresh-study.json

python research/hcsn/p4_round2_online.py \
  --features research/hcsn/fixtures/frozen_round2_20261105.npz \
  --study research/hcsn/gates/2026-11-05-round2-p3-natural-rejection-raw.json \
  --clip-source /path/to/CLIP --cache /path/to/asset-cache \
  --output /path/to/fresh-online.json
```

The feature acquisition uses pinned public inputs and checks their recorded
identities. Re-encoding produces a new compressed NPZ receipt; ZIP metadata
need not make a fresh NPZ byte-identical, while tensor values and source
identities can be compared. The committed fixture is hashed exactly.

## Remaining blockers

Real audio/video encoders and true temporal alignment; missing-content inference;
joint semantic contradiction reasoning; broad independently calibrated unknown
inputs; positive HCSN benefit beyond ordinary parameterization and memory;
learned net compute saving; accelerator/energy/communication qualification; and
external independent acceptance remain unresolved. Local numerical tests,
source consistency, a fixed-quality cache speedup, and a better rejection score
do not close those broader requirements.
