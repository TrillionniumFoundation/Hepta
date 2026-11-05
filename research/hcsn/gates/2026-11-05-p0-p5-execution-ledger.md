# HCSN P0–P5 execution ledger — 2026-11-05

This ledger uses the user's current six-stage numbering. It does not rewrite
the older P0–P6 gate schema, substitute unit tests for scientific evidence, or
inherit acceptance between different source branches. Main remains
`125d11c5454835a7df1dc51915fc49901fbede5b`; these are research Drafts.

## Source identities and evidence navigation

| Work | Exact source / checkpoint | Evidence |
|---|---|---|
| P0 continuous original-HX obstacle | [#527, `069ff1ee1f65baff65a0b12340e68cfdae0b2588`](https://github.com/TrillionniumFoundation/Hepta/commit/069ff1ee1f65baff65a0b12340e68cfdae0b2588) | [Round-3 proof and all 60 outcomes](https://github.com/TrillionniumFoundation/Hepta/blob/069ff1ee1f65baff65a0b12340e68cfdae0b2588/research/hcsn/gates/2026-11-05-round3-p0-global-obstacle.md) |
| P1 / P5 exact feature controls and tiny causal generator | [#513, `499bb727b417a077473390b98c1707b183baf4cf`](https://github.com/TrillionniumFoundation/Hepta/commit/499bb727b417a077473390b98c1707b183baf4cf) | [Committed 21-model experiment](https://github.com/TrillionniumFoundation/Hepta/blob/499bb727b417a077473390b98c1707b183baf4cf/research/hcsn/gates/2026-11-05-round2-causal-lm.md) |
| P2 prior raw-token campaign, published this continuation | [#512, `5acfdc3655a9838c7e2b5f936c1d4f6c2ff0da79`](https://github.com/TrillionniumFoundation/Hepta/commit/5acfdc3655a9838c7e2b5f936c1d4f6c2ff0da79) | [All six old fits and failures](2026-11-05-round2-p2-raw-token-report.md) |
| P2 new learned associative memory | [#512, `04cc4d982c2b09dee144cd06a0ecf8f7f32c5539`](https://github.com/TrillionniumFoundation/Hepta/commit/04cc4d982c2b09dee144cd06a0ecf8f7f32c5539) | [Four fits, eight panels, reset failures](2026-11-05-round2-associative-report.md) |
| P3 new causal image-text source matching | [#512, `d431b0b1e86e5bc62d3c38b54f7b2980c6ed515a`](https://github.com/TrillionniumFoundation/Hepta/commit/d431b0b1e86e5bc62d3c38b54f7b2980c6ed515a) | [Frozen protocol, corrected results and audit](2026-11-05-round3-p3-causal-alignment.md) |
| P2 exact-event reset/validity preregistration | [#512, `b9571fb1de3c420ceaea27152f59898e36795dfe`](https://github.com/TrillionniumFoundation/Hepta/commit/b9571fb1de3c420ceaea27152f59898e36795dfe) | [Protocol and hashed sources](2026-11-05-round3-p2-reset-validity-protocol.json) |
| P2 fixed completion preregistration and original budget-stop evidence | [#512, `fa8eb7413d72762f51e61144c36912047dfce240`](https://github.com/TrillionniumFoundation/Hepta/commit/fa8eb7413d72762f51e61144c36912047dfce240) | [Completion protocol](2026-11-05-round3-p2-reset-validity-completion-protocol.json), [executed reset/validity report](2026-11-05-round3-p2-reset-validity-report.md) |

## What the current evidence resolves

### P0: mathematics

The four mathematical objects remain separate:

1. **Original HX:** debt price, rollover cashflow and endogenous candidate
   boundary are retained. New continuous interval covers plus an analytic tail
   certify the specified fixed-debt-price stopping problem on additional
   parameter sets. This does not establish equilibrium uniqueness when debt
   is repriced under arbitrary deviations.
2. **Simplified stopping kernel:** the simpler one-shot stopping problem has
   its own analytic boundary and independent numerical comparisons. Its
   Call/Put algebra is not automatically an original-HX equity identity.
3. **Fixed-policy regeneration:** renewal value evaluates an already supplied
   threshold/reset policy. A correct repeated-cycle value is not evidence
   that the policy is optimal.
4. **Optimal QVI:** the fixed-reset numerical/analytic controls remain
   distinct from unrestricted, state-dependent reset choice and a neural
   control objective. The general problem is not closed by the HX certificate.

On the unchanged 20-tuples × three input contracts panel, sufficient
certificates increase from 37 to 41. The remaining outcomes are seven local
obstacle counterexamples, three nonpositive candidates and nine unresolved
quantized inputs. These are finite-panel categories, not a percentage of the
full legal parameter space. Every accepted interval cover includes all states
in its finite intervals and the infinite tail. The 120 distinct mathematics
tests and independent MP checks validate implementation under those contracts.

### P1: mechanism attribution

The requested Call-only, Put-only, margin-only, dual, Put+linear and ordinary
controls are present in the existing source-exact studies. For the simplified
pair, `C-P=u-1`; with immediate affine consumers, Call/Put and Put+linear
have equal function classes under an explicit invertible weight map.
Additional independent Call information/capacity is therefore refuted in that
specified architecture. Native optimizer coordinates can still differ.

This identity is an exact-arithmetic statement. A hard event can amplify a
one-ULP logit difference into different reset decisions; the new P2 preflight
retains an explicit FP32 threshold counterexample. Neither soft-output
agreement nor the identity alone certifies all floating-point event histories.

No stable HCSN-specific benefit over matched ordinary controls is established
by the bounded memory, image-text or tiny-generator experiments. A positive
claim needs a new falsifiable hypothesis; old fixed negative results remain.

### P2: memory and regeneration

The old compressed raw-token model has been independently replayed over
51,504 queries, with exact predictions and probabilities. It remains a
negative result; it was not silently replaced by the new structural model.

The new learned 8-by-16 associative state uses raw tokens and learns addresses,
writes and erasure from answer loss. Both ordinary seeds and HCSN seed 503
pass seven of eight bounded panels. HCSN seed 401 fails all eight. Every run
misses the repeated-reset 90% whole-sequence target. The three otherwise
learned fits' 23/12/17 errors are false known answers where UNKNOWN is required.
All four fits and 25,728 heldout queries were retained and replayed exactly.

The registered hard-reset/validity intervention has now been executed. Both
ordinary and HCSN controls share learned hard write/reset events and an
explicit validity vector; true event labels and semantic-token branches are
excluded. Reset clears old state before any overflowing inner product, with
an explicit FP32/FP64 contract. Conditional erasure, correct semantic timing,
and task accuracy are separate questions.

The original 180-second training budget stopped after three complete fits
and 173 updates of the fourth. Its result and all four weights remain
`INCOMPLETE_RETAINED`. A separately published completion protocol reused the
three final weights and replayed the fourth from identical initialization,
because the original optimizer state was not saved. Every one of its first
173 losses and gradient norms, and all checkpoint tensor dtypes/shapes/bytes,
matched before completing 300 updates and constructing heldout panels.
This is five actual fit attempts for four final configurations, 1,373 actual
updates and 119,300 training query labels. Combined recorded campaign cost
is 240.1887 process CPU seconds, including 173 replayed updates; the original
180-second budget does not become a pass.

All four final models fail all nine quality panels: 39,552 query predictions
are UNKNOWN, including every one of the 23,404 queries that required a known
answer. Whole-sequence exact accuracy is zero in every model/panel pair.
Zero UNKNOWN false accepts and detected reset windows cannot compensate for
this complete known-answer rejection. The inherited `stale_answers_emitted`
counter can count a previous UNKNOWN label; it is not by itself a measure of
leaking an old known value. The raw metric is retained with that qualification.
Independent replay verified all 36 primary model/panel combinations, all 18
mapped Put+linear model/panels, and four conditional-erasure witnesses. Actual
old-known-value emissions are zero; each fit's 3,576 legacy stale counts are
previous UNKNOWN labels. Each fit has zero exact sequences out of 864.

A separate 36-case autograd analysis, with no fits or dataset/checkpoint
reads, identifies a conditional learning dead zone. When reset=1 at a query,
both the address and memory/validity are zero. Their two-factor products
have zero first derivative toward the controller, despite the STE. UNKNOWN
probability is then `sigmoid(6)` (about 0.997527). Future nonreset queries can
still backpropagate through earlier state: this is not global unlearnability.
The registered quality-and-reset hypothesis fails for both modes; the model
was not changed or retuned after that observation.

Ordered Selective Copy, arbitrary/new keys, non-adjacent syntax, autonomous
continuous-time events and full P2 scientific acceptance remain open.

### P3: real modalities

Frozen official CLIP and real COCO/SugarCrepe features are used. The new
pair scorer genuinely consumes query text and observed historical visual
embeddings. It performs causal single-direction source matching with missing
frames, bounded eviction, delays and observed physical times. Label metadata
no longer participates in the inference adapter; its former dependency and
the exact repair replay are retained.

Delayed-source recall is about 99.1% for Call/Put, ordinary and the smaller
raw-cosine control, versus zero for time-only-newest. Call/Put does not have a
consistent advantage. The random four-candidate task is close to ceiling;
the preregistered +2-point uniform improvement criterion cannot be generalized
into a rejection of all possible mechanisms.

This is not bidirectional recurrent fusion, natural audio/video alignment,
missing-content inference or novel-class rejection. The irregular panel's
target is age zero, so irregular delays of old targets remain untested there.
The 112 test captions, three seeds and multiple panels reuse 97 original
images, already used previously. Independent accounting replay covers 105
model/panel combinations, but does not create independent statistical samples.

### P4: efficiency

The prior exact-input cache experiment ran the actual CLIP online path and
preserved identical complete output traces: 30.21922 to 4.20939 online seconds
(7.1790×) on a constructed repeat-heavy sequence. Including whole-process
startup/loading/warmup changes the observed ratio to 2.6107×. This is ordinary
exact caching, not evidence that HCSN learned beneficial skipping; the smaller
overwrite control was cheaper.

Cost review removed an unused analytic calculation from the ordinary scorer.
All 42 frozen model/panel outputs and six complete parameter/input gradient
comparisons remain elementwise exactly equal under `torch.equal`. Corrected complete FIFO/scorer/validation
CPU forward medians are 3.4676 ms Call/Put, 3.2355 ms ordinary and 1.9455 ms
cosine, B=8/T=12. The older cost comparison remains in its raw receipt but is
superseded by this randomized interleaved measurement. These measurements
exclude encoding and network; qualities differ. They are not a fixed-quality
full-system speedup or production p99 qualification.

The available execution environment exposes no CUDA/DRM device or hardware
powercap energy counter. Actual joules, accelerator kernels and distributed
communication costs remain unmeasured. CPU seconds are not converted to energy.

### P5: scale

The preserved current #513 experiment really trains the complete small causal
byte generator (32,176 parameters), including embeddings, attention, both
internal FFN replacements, norms and decoder. Twenty-one model runs cover
three seeds and 1/2 or 2/2 replacement. It is not a head-only experiment.

Dual has worse heldout bits-per-byte in all 12 paired seed/document/replacement
comparisons. The two related project-document test files are not an independent
large corpus; this is neither medium/large encoder training nor useful
large-model generation qualification. Scaling remains open and the failed
fixed small-model gain criterion remains preserved.

## Remaining exit conditions

| Stage | Concrete remaining requirement |
|---|---|
| P0 | General reset-choice QVI verification; original-HX scope under repricing; native full-state low-precision values/gradients and certified event behavior |
| P1 | Incremental mechanism benefit beyond reparameterization, state size, slope and optimizer effects on a new frozen task family |
| P2 | Accurate learned reset/write/UNKNOWN behavior across all seeds and complete sequences; ordered Selective Copy and broader key/syntax/time domains |
| P3 | Difficult content alignment and truly interacting temporal modalities, unused test material, calibrated semantic unknowns and real audio/video |
| P4 | Fixed-quality end-to-end costs including controllers, real device energy and communication on the target hardware |
| P5 | Preserved quality/cost benefit when expanding to medium encoder and generator backbones under fixed budgets |

Internal independent computational review is retained. It is not an external
independent scientific attestation. Draft status and production-disabled
state remain appropriate; no scientific stage is marked complete merely
because its source or unit tests were published.
