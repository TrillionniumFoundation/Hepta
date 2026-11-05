# Round 2: global feature coordinates and a small end-to-end causal generator

Research evidence recorded 2026-11-05 UTC on base
`9bfadcb94adee38406c842f17bc4d337033236a8`, existing Draft PR #513.
**The fixed positive-gain hypothesis fails: ordinary sigmoid control has lower
heldout bits per byte in all 12 paired seed/document/replacement comparisons.**
The dual and Put + linear function classes are exactly isomorphic under the
stated affine-consumer conditions. Their independently optimized native Adam
coordinates can nevertheless learn different functions.

This closes several specific negative questions below. It does not close the
overall P1 scientific acceptance or the user's P5 scale gate, and it does not
activate production. The historical `GATES.md` used P6 for scale; this report
uses the user's current P5 numbering.

## What was actually trained

This is a 32,176-parameter causal byte language model trained from scratch.
Token and position embeddings, two causal multihead attention blocks, both
internal feedforward modules, all layer norms, and the vocabulary decoder
receive gradients and change during training. Both the last 1/2 and all 2/2
internal feedforward modules are replaced. Attention itself is unchanged.
This is an end-to-end generator experiment, not a frozen representation head
probe. It transfers the simplified stopping activation; it is not a trained
original-HX equilibrium, optimal QVI, or autonomous spiking network.

| Fixed element | Executed setting |
|---|---|
| Vocabulary | All 256 literal UTF-8 bytes; no learned tokenizer or normalization |
| Architecture | Width 32; two blocks; four attention heads; feedforward width 24; context 64; no dropout |
| Training | Seeds 11, 23, 37; batch 4; 240 updates; 61,440 target bytes per model |
| Optimizer | Adam, learning rate 0.003, betas (0.9, 0.999), epsilon 1e-8; no weight decay or clipping |
| Compute | FP32 CPU; PyTorch, OMP, MKL, and OpenBLAS restricted to one thread |
| Checkpoint | Final fixed update only; no heldout checkpoint selection or hyperparameter search |
| Runs | 21 models: three controls for each replacement fraction, plus one ordinary baseline per seed reused for both comparisons |
| Evaluation | Next-byte cross entropy on fixed document windows; also 32 actual autoregressive generation steps from a 16-byte prompt per document |

All configurations have exactly 32,176 trainable parameters. Matching parameter
count, training examples, and updates does not match transcendental-operation
counts, backward FLOPs, or elapsed time. In particular the ordinary sigmoid
control is a different function class despite its equal parameter count.

The data are real project documentation already present at the pinned base:
five complete training documents containing 55,848 bytes, and two whole
heldout documents containing 15,434 bytes. Every file's byte count and SHA256
is fixed in `2026-11-05-round2-causal-lm-protocol.json`. Training windows never
cross document boundaries. The heldout check searches every training start
for exact 65-byte input/target span duplication; none of the 240 candidate
heldout spans were duplicated. Evaluation selects 34 windows / 2,176 target
bytes from `docs/COMPATIBILITY.md` and 64 windows / 4,096 target bytes from
`docs/AGENT_PROTOCOL.md`. The raw evidence includes selected offsets and
window-content hashes, plus every training document-index/offset pair and
the sampled-byte hash for each seed.

Whole-document splitting and this exact-span check do not make two related
documents independent corpora. Short shared phrases, vocabulary, and subject
matter remain. The same 98 heldout windows are reused by all seeds and modes;
there are not 21 independent test corpora. The literal byte vocabulary table
`bytes(range(256))` has SHA256
`40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880`.
The tokenizer implementation is covered by the executed source hash as well.

The protocol was fixed before the runs, with SHA256
`075cfece3308be4d9b429cb6b953711205f6866ddc188c9ef88c775d45af69a9`.
This is a local prospective experiment, not an independently preregistered
public benchmark. Its predeclared positive criterion required dual to improve
both documents in every paired seed at both replacement fractions.

## Global function and signed-gradient control

For the implemented simplified pair, at every positive normalized input u,

\[
C(u)-P(u)=u-1=:L(u).
\]

The identity covers the stopping region, continuation region, and their C1
boundary. Each replaced module uses `u=0.01+softplus(W_in x+b_in)`, which stays
inside this domain. Its immediate output is affine in `[C,P]`. The invertible
weight change is

\[
(W_C,W_P)\longmapsto(W'_P,W'_L)=(W_C+W_P,W_C),
\]

with inverse `W_C=W'_L`, `W_P=W'_P-W'_L` and unchanged bias. Therefore every
whole-network function obtainable by these dual modules is obtainable by
Put + linear modules, and conversely. This also preserves signed derivatives
with respect to upstream continuous inputs and the complete upstream parameter
path. The result follows from algebra, not from agreement of a finite sample.
It does not extend to extra channel-specific nonlinearities, dropout,
constraints, quantization, or original coupled HX equity without a separate
argument. Here “linear” means affine in u, not affine in the raw token input.

Four controls separate capacity, initialization, and optimization:

| Control | Features and parameter coordinates | Interpretation |
|---|---|---|
| Dual | `[C,P]`, canonical `(W_C,W_P)` | Candidate internal activation |
| Put + linear, native Adam | `[P,L]`; initial weights mapped to the same function; Adam updates native `(W'_P,W'_L)` | Same function class and initial function, different optimizer coordinates |
| Put + linear, canonical Adam | `[P,L]`; compute mapped weights from canonical `(W_C,W_P)` on every forward pass | Pull the complete gradient back through the mapping before Adam |
| Ordinary sigmoid tangent | `[P_sigmoid,L]`, same canonical output coordinates and initialization | Equal width/parameter count with boundary value and signed slope matched; different global shape |

For the ordinary control, with boundary b,

\[
P_{\rm sigmoid}(u)=2(1-b)\,\operatorname{sigmoid}
\!\left(-\frac{2(u-b)}{1-b}\right),
\qquad P_{\rm sigmoid}(b)=1-b,\quad P'_{\rm sigmoid}(b)=-1.
\]

This is only a local tangent match. Its tail and curvature differ from P.
Equal values and signed derivatives everywhere would, on a connected domain,
force the same function up to the matched constant; that global control is
provided by the exact Put + linear mapping, not by calling the sigmoid global.

Writing native gradients as `(g_P,g_L)`, the pullback is
`(g_C,g_Pold)=(g_P+g_L,g_P)`. The tests compare every network parameter, including
embeddings, attention, and normalization, after this transformation. Exact
arithmetic canonical gradients and deterministic optimizer states coincide
under the map. Native-coordinate Adam is not invariant to this nonorthogonal
change, so same initial functions do not imply identical trained functions.
No literal trainable-token Jacobian is claimed: byte IDs are discrete.

## Actual heldout results

Bits per byte are lower when next-byte predictions are better. Each cell is
the arithmetic mean across the same three training seeds; all per-seed values,
per-window losses, 240-step loss curves, and generation bytes are in the raw
JSON. Standard deviations below describe training-seed variation only.

| Model | Replaced blocks | COMPATIBILITY bpb, mean ± seed SD | AGENT_PROTOCOL bpb, mean ± seed SD |
|---|---:|---:|---:|
| Ordinary sigmoid tangent | 0/2 | 3.865671 ± 0.018552 | 4.066188 ± 0.015143 |
| Dual | 1/2 | 3.876892 ± 0.025761 | 4.075162 ± 0.014000 |
| Put + linear, canonical Adam | 1/2 | 3.876892 ± 0.025761 | 4.075162 ± 0.014000 |
| Put + linear, native Adam | 1/2 | 3.865220 ± 0.016305 | 4.064377 ± 0.003309 |
| Dual | 2/2 | 3.877559 ± 0.028482 | 4.079501 ± 0.016356 |
| Put + linear, canonical Adam | 2/2 | 3.877559 ± 0.028482 | 4.079501 ± 0.016356 |
| Put + linear, native Adam | 2/2 | 3.890441 ± 0.031116 | 4.091182 ± 0.016353 |

The paired values make the negative result inspectable rather than relying on
rounded means. Positive dual-minus-ordinary means the candidate is worse.

| Seed | Replacement | Dual − ordinary, COMPATIBILITY | Dual − ordinary, AGENT_PROTOCOL | Native PL − dual, COMPATIBILITY | Native PL − dual, AGENT_PROTOCOL |
|---:|---:|---:|---:|---:|---:|
| 11 | 1/2 | +0.009579 | +0.009393 | -0.008272 | +0.001627 |
| 11 | 2/2 | +0.009421 | +0.014008 | +0.049810 | +0.026408 |
| 23 | 1/2 | +0.004817 | +0.004975 | -0.003739 | -0.017309 |
| 23 | 2/2 | +0.003196 | +0.016943 | +0.018160 | +0.011730 |
| 37 | 1/2 | +0.019268 | +0.012553 | -0.023007 | -0.016674 |
| 37 | 2/2 | +0.023047 | +0.008986 | -0.029325 | -0.003093 |

Dual loses all 12 paired bpb comparisons. This resolves the predeclared
uniform-gain criterion negatively on this protocol. These correlated rows
are not 12 independent trials, and no broad population significance is inferred.
Native PL sometimes improves and sometimes worsens the result; its changed
function is compatible with optimizer-coordinate effects, not additional
capacity or independent Call information. Slightly better native PL means at
1/2 replacement do not establish a general gain either.

All configurations learn: the minimum nonzero change over each model's five
major parameter groups is 0.1632. Teacher-forced byte accuracy remains about
21–23%. The separately executed greedy continuations have 0–12.5% exact
positionwise byte accuracy on these two 32-byte continuations; this is not a
claim of useful generation quality. Canonical and dual produce the same
recorded greedy bytes in this experiment. The purpose is to test a real causal
training path with a falsifiable comparative outcome.

## Floating point trajectories: functional agreement is not parameter equality

The predeclared numerical threshold was **1e-5 heldout bpb**, not a parameter,
logit, or gradient tolerance. The maximum final canonical-minus-dual bpb
difference is **1.8743422e-7** over all 12 comparisons. This passes that specific
check. During all 240 FP32 training steps, the maxima are:

| Quantity | Maximum across six paired training conditions |
|---|---:|
| Initial native PL versus dual logits | 1.7881393e-7 |
| Initial full native-gradient pullback versus dual | 4.4703484e-8 |
| Canonical versus dual training loss | 1.4305115e-6 |
| Canonical versus dual full gradients | 1.0520220e-5 |
| Canonical versus dual logits | 9.5129013e-4 |
| Canonical versus dual parameters | 7.2264895e-3 |

The later gradient differences include the effects of already diverged FP32
parameters; they are not a single fixed-point roundoff certificate. The final
bpb comparison does not bound all logits, gradients, or future inputs, and the
parameter trajectories are measurably different. Separate FP64 tests verify
whole-network functions and pulled-back gradients, and four canonical Adam
steps, within their stated tolerances.

A limited post-result diagnostic replays only seed 37 with 2/2 replacement for
dual and canonical PL. Its 240 losses for each model are exactly equal to the
already recorded losses, so it examines the original condition rather than a
different training sample. It records every parameter's drift and gradient
range in `2026-11-05-round2-causal-lm-drift-audit.json`.

The largest drift is `blocks.0.qkv.bias[34]`, inside its key-bias slice 32:64:
the final dual value is -0.0037159508 and canonical value +0.0035105390.
In exact attention, adding a common key bias adds `q_i dot b_key` to every
admitted key logit of query i, which softmax cancels. This is a parameter
direction that does not change the mathematical function. FP32 backward still
produces small residual gradients: maxima 2.7648639e-9 and 3.3901415e-9, with
maximum gradient difference 4.3241926e-9. Adam with epsilon 1e-8 can accumulate
these residuals. The final first-moment scale is about 2.5e-10 and square-root
second-moment scale about 3.4e-10.

Excluding both key-bias slices, the maximum parameter gap over this diagnostic
is 4.2103231e-5, in `blocks.1.qkv.weight`. Replacing only canonical key biases
with dual key biases changes heldout logits by at most 2.8610229e-6; the remaining
dual/canonical logit difference is still about 1.8e-5. Thus the largest parameter
drift is explained by the softmax zero direction, while smaller functionally
relevant numerical differences remain. This one-condition diagnosis does not
assert every drift in every seed has the same cause.

## Scoped negative closure ledger

| Specific question | Disposition | Basis and boundary |
|---|---|---|
| Does Call add independent information given Put and normalized linear payoff? | CLOSED NEGATIVE | `C-P=u-1` globally for this simplified pair |
| Does dual have greater capacity than Put + linear in the implemented affine-consumer networks? | CLOSED NEGATIVE | Explicit invertible weight map, including whole generator composition |
| Is the previously missing Put + linear control still a blocker? | RESOLVED | Round 1 head controls plus round 2 whole-network controls |
| Must different native Adam results imply a special free-boundary mechanism? | CLOSED NEGATIVE | Matched initial functions and full gradient pullback; native optimizer changes coordinates |
| Does dual outperform ordinary in the fixed legacy Bayes READ protocol? | CLOSED NEGATIVE FOR THAT PROTOCOL | Source-exact round 1 replay retained; ordinary regret is lower |
| Does dual satisfy this tiny LM's predeclared gain criterion at both replacement fractions? | CLOSED NEGATIVE FOR THIS PROTOCOL | Higher bpb in every paired comparison |
| Can the module be trained inside an actual causal generator with the surrounding network? | OBSERVED IN THIS SMALL MODEL | All major parameter paths trained; causality checks and actual generation executed |
| Is canonical FP32 optimization bitwise or parameterwise identical? | CLOSED NEGATIVE | Nonzero recorded parameter/logit/gradient gaps, with bounded diagnostic |
| Does canonical training meet its declared final bpb tolerance? | SUPPORTED IN THIS RUN | 1.8743422e-7 maximum, against 1e-5 threshold |
| Is there a general independent mechanism gain or large-scale quality/cost advantage? | NOT ESTABLISHED | Two related documents, 32,176 parameters, no medium/large model or quality-matched energy comparison |

Negative questions above should not remain indefinitely pending as if a
positive result were merely awaiting more repetitions. A future positive
claim requires a new, clearly scoped hypothesis and independent evidence;
it cannot replace or retune away these fixed negative results. The old reports
and raw evidence are retained unchanged.

## Executed checks and total cost

Five focused tests pass, zero failures and zero skips: global feature/signed
slope identity; full-network function and gradient pullback at both replacement
fractions; four-step canonical Adam versus the native-coordinate counterexample;
prefix causality in every mode; and document-window provenance/overlap guards.
The retained log records the actual test execution. The independent mathematical
review found no blocker in the feature map, gradient pullback, or ordinary
tangent definition. It specifically cautioned that timing includes unequal
audit overhead, as disclosed here.

The same five tests also pass through `unittest discover`; the import fallback
was added for the repository's documented discovery command. Both receipts
are retained. They are five unique checks, not ten independent tests.

The entire 21-model child process, including imports, corpus preparation,
training, diagnostics, all evaluation/generation, and output serialization,
used 61.264820 seconds wall time, 57.180546 seconds user CPU plus 1.861206 seconds
system CPU, and 303,759,360 bytes peak RSS. The extra two-model drift diagnostic
used 7.031338 seconds wall and 6.607407 seconds process CPU inside its measured
scope. Per-mode training times include every-step gradient/logit copies for
dual and canonical PL, but not the same copies for native PL and ordinary.
They therefore do not provide a fair operator-speed comparison. The shared
host, absence of hardware energy counters, and unmatched FLOPs preclude a P4
quality-cost acceptance claim.

The first measurement launch failed with exit 127 because `/usr/bin/time` was
absent; the model did not start. Its stderr is retained. A stdlib subprocess
runner then executed the complete campaign successfully and captured whole
child CPU/RSS and its actual exit code. The campaign and diagnostic refuse
to overwrite their original evidence outputs.

## Reproduce on the published commit

Use Python 3.12.14, PyTorch 2.10.0+cpu and NumPy 2.3.5 for the recorded local
environment. The execution manifest includes base/source/protocol/artifact
hashes and every retained command result. Existing corpus files are verified
before training; no corpus download or trained tokenizer is required.

```sh
export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
python -m unittest research.hcsn.test_round2_causal_lm -v
python -m research.hcsn.round2_causal_lm_runner --prefix /tmp/hcsn-round2-new
python -m research.hcsn.round2_causal_lm_drift_audit \
  --raw /tmp/hcsn-round2-new-raw.json \
  --output /tmp/hcsn-round2-drift-new.json
```

The published manifest covers the frozen protocol, full raw evidence, original
stdout/stderr, whole-process cost, failed launcher receipt, limited diagnostic,
test log, source files, this report, and the gate-ledger addendum. No remote
publication or production acceptance is performed by these scripts.
