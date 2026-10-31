# HCSN P2 iteration 16 — causal checkpoint free-boundary first-hit reference (research-only)

**Admission: DENY_ALL / NO_GO. Every scientific P0–P6 gate remains OPEN.**

## Why this experiment exists

Existing HCSN P2 branches establish fixed-barrier renewal laws, two-state Markov mode resets, time-dependent post-hit resets, and a learned content-conditioned boundary. They do not independently verify even the bounded-domain first-hitting risk after a *causal input/state-dependent barrier jump*. This increment supplies a new, independent two-stage oracle; it does not replace the original He–Xiong full financial coupling or claim new neural learning gains.

## Explicit model / proof sketch

Use `X_t = x0 + mu*t + sigma*W_t`. Absorb at constant `b1<x0` up to time `t1`. Conditional on surviving and observing `Y=X_t1`, select the new barrier

`b2(Y)=b2_level+gain*(Y-x0)`, with `gain ∈ [-0.75,0.75]`, and freeze that threshold until `T=t1+t2`. The policy depends on the current checkpoint state only; no future state is accessed.

For `y>b1`, define the exact killed transition density via the reflection principle:

`p_abs(y) = normal_pdf((y-x0-mu*t1)/(sigma*sqrt(t1)))/(sigma*sqrt(t1)) * [-expm1(-2*(x0-b1)*(y-b1)/(sigma*sigma*t1))]`.

The constant-barrier future first-hit probability for positive distance `d` is

`F(t;d) = Phi((-d-mu*t)/(sigma*sqrt(t))) + exp(-2*mu*d/sigma**2)*Phi((-d+mu*t)/(sigma*sqrt(t)))`.

A barrier jump can itself cause an immediate event. As `gain<1`, survival after the switch requires

`Y > ell=max(b1,(b2_level-gain*x0)/(1-gain))`.

The exact *probability identity* for this restricted policy is

`P(hit by T) = 1 - Integral_{ell}^{infinity} p_abs(y) * [1-F(t2;y-b2(y))] dy`.

The identity follows from killing at `b1`, conditioning at the checkpoint and the strong Markov property. **Numerical integration is not an analytic closed form, nor a mathematically certified enclosure.** The PyTorch fixed-node integral provides a differentiable FP64 computational reference; its small measured quadrature gap is not a universal error guarantee.

## Executed local evidence (CPU only, 2026-10-31)

- **9/9 focused tests PASS**, zero skips: fixed-barrier semigroup for 9 drift/barrier configurations, killed density boundary, barrier-jump monotonicity, causal state feedback, SciPy adaptive-vs-PyTorch Gauss-Legendre integration, five-panel exact-checkpoint Brownian-bridge MC, signed 8-coordinate autograd vs independently computed central finite differences, invalid-parameter rejection, and causal interface assertions.
- Five parameter panels, deterministic seeds `20261031..20261035`, **160,000 MC trajectories each** (800,000 total), exact-in-continuous-time bridge-crossing probability *per frozen interval*, including instantaneous jump: maximum descriptive |z| **1.3069** (not a preregistered confirmatory acceptance test).
- Maximum absolute SciPy adaptive vs fixed 256-point FP64 Gauss-Legendre gap across these five cases: **2.78e-15**. This is an observed panel value only, not a global theorem.
- Stationary semigroup collapse verified against independent reflection-principle first-hit CDF, three drifts and three fixed barriers.
- Representative risk: initial `x0=1.15`, first barrier `b1=0`, checkpoint policy `b2(Y)=.4+.32*(Y-1.15)`, `mu=.08`, `sigma=.65`, `t1=.75`, `t2=.9` gives `P_hit≈0.25099875`; paired MC gives `0.250425`.
- Scalar CPU latency **illustrative only**: SciPy adaptive quadrature median ~7 ms, PyTorch 256-node FP64 median ~0.19 ms for 110 local warm repetitions. This is not whole-model throughput, no CUDA, no GPU power, no event scheduler, no controlled cross-host performance test.

`research/hcsn/gates/2026-10-31-iteration16-checkpoint-evidence.json` contains the five complete parameter panels, independent MC errors, signed source digests and local timing observations. No external evaluator/observer signatures were issued.

## Reproduce on exact branch

From repository root (scipy, numpy, torch CPU):

```sh
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_checkpoint_boundary_oracle -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_checkpoint_boundary_evidence
```

## Non-closure and next proof obligations

- **P0 OPEN:** full coupled original HX financial model, dynamic QVI existence and bounds, all-domain BF16/FP32.
- **P1 OPEN:** same-compute, same-parameter, signed-slope causal advantage; preserve prior null/negative studies.
- **P2 OPEN:** learned many-event content memory, long Selective Copy/MQAR with independently optimized baselines, dynamic continuous-time barriers (here only one checkpoint), autonomous multi-reset, event gradients, durable crash recovery. Different checkpoint feedback values produce different risk probabilities but do not establish learning utility.
- **P3–P4 OPEN:** pretrained real text/audio/vision/video and heldout cross-modal semantic/time/entity data.
- **P5 OPEN:** fused kernels, target GPU, physically measured Joules and full-network RSS/p95/p99.
- **P6 OPEN:** frozen-budget medium Encoder quality–cost frontier.

**Production activation remains false.** No main merge and no production route edits. This is a scientific reference artifact stacked on the existing HCSN research branch, not release evidence.
