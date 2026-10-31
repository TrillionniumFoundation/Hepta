# HCSN P2 iteration 17 — causal, continuously moving free-boundary first-hit reference

**Research only. DENY_ALL / NO_GO. ALL P0–P6 scientific gates OPEN. `production_activation=false`.**

## Exact lineage and scope

- Stack only on `TrillionniumFoundation/Hepta` Draft PR #498, frozen HEAD `c6631f7939cf0d9008026b4e5762d80e577827cd` at start of this iteration. PR #498 inherits #492 and earlier HCSN draft research. Do NOT overwrite prior exploratory results or touch main/release/production code.
- #498 independently handles a causal **checkpoint jump** between two piecewise-*constant* barriers. This iteration extends to **linear continuous drift of each barrier within the stage**, with a causal checkpoint-state-dependent second-level choice.
- Does not solve the original He–Xiong coupled rollover-equity/default model, nonlinear/general moving boundaries, a self-consistent regenerative QVI, or a trained multi-event memory model.

## Derivation: an exact one-dimensional probability identity

Let `X_t=x0+mu*t+sigma*W_t`, `sigma>0`; stop at the lower boundary `B1(t)=b1+s1*t` up to time `t1`. On survival, observe `Y=X(t1)`; choose the next barrier **only from currently observed Y**:

`B2(u;Y)=b2+g*(Y-x0)+s2*u`, `0<=u<=t2`.

A jump to a barrier above Y at the checkpoint triggers immediate hit. For `g<1`, the minimum checkpoint state surviving both the first stage and jump is

`ell=max(b1+s1*t1,(b2-g*x0)/(1-g))`.

For `y>b1+s1*t1` set `d0=x0-b1`, `d1(y)=y-b1-s1*t1`, `S1=sigma*sqrt(t1)`. The **killed** first-stage density of `Y` is

`q1(y)=phi((y-x0-mu*t1)/S1)/S1 * [1-exp(-2*d0*d1(y)/S1²)]`.

This follows by applying the Brownian bridge crossing law to `X_t-s1*t`, whose drift becomes `mu-s1` while its barrier becomes constant. The original free Gaussian density is in X coordinates (with drift mu). The second-stage distance from the **jump-selected** barrier is `d2(y)=y-b2-g*(y-x0)`, and relative drift is `mu-s2`. For positive d the reflection-principle CDF is

`F(d,nu,sigma,t)=Phi((-d-nu*t)/(sigma*sqrt(t)))+exp(-2*nu*d/sigma²)*Phi((-d+nu*t)/(sigma*sqrt(t)))`.

By conditioning on Y and the strong Markov property,

`P(any hit up to t1+t2)=1 - integral_[ell,inf) q1(y)*[1-F(d2(y),mu-s2,sigma,t2)]dy`.

**This is an exact probability identity for the restricted two-line causal model.** Its SciPy adaptive and fixed-node PyTorch integrals are numerical approximations; their matching panel output is NOT an all-parameter guaranteed error bound. `torch` implementation exposes FP64 gradients with respect to all ten scalar parameters except at active-set switches, where differentiability cannot be presumed.

### Independent oracle and reductions

- Brownian bridge Monte Carlo: sample free Gaussian endpoints independently for each stage; sample exact conditional Brownian-bridge crossing events against the stage's linear boundary. No first-passage CDF, quadrature, Euler grid or downstream model code is used.
- Global straight-line reduction: if `g=0`, `s1=s2=s`, `b2=b1+s*t1`, the two stages reduce exactly to `F(x0-b1,mu-s,sigma,t1+t2)`.
- Prior fixed-barrier reduction: `s1=s2=0` reproduces the #498 two-stage probability for identical parameters (0.2509987539500086).

## Executed local validation (Python CPU, FP64; 2026-10-31)

- **9/9** unittest methods PASS, 0 skips. Includes nine global-line drift/slope reductions, both-slope probability monotonicity, causal interface, near-boundary killed density, fixed-stage regression, robust input rejection, independently integrated signed gradients, and Brownian-bridge MC.
- **Six deterministic panels × 180,000 paths = 1,080,000 exact-within-stage Brownian-bridge trajectories**; maximum |descriptive z| = **1.78587800046**. Descriptive only; test cases were not independently preregistered.
- Six adaptive SciPy vs PyTorch 256-node quadrature cases: max absolute observed gap **1.44328993201e-15**. **150** seeded randomized moderate-domain parameter cases: max absolute observed gap **3.88578058619e-15**. These values are *observed agreement*, not global certification.
- All **ten** signed FP64 PyTorch autodiff gradients checked against independent adaptive quadrature central finite differences: max absolute error **7.20860082737e-09** on one interior point. Active-set switch gradients and BF16/FP32 conditioning are unqualified.
- Illustrative scalar eager CPU FP64 median recorded in JSON; it is NOT a p99/full-model, GPU, RSS, watt or Joule measure.
- The evidence JSON includes all six panel parameters, signed gradients, counts/standard errors and source SHA256. It is deterministic except incidental CPU timing and contains no third-party observer signature.

## Exact reproduction

```sh
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_p2_moving_affine_boundary -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m research.hcsn.p2_moving_affine_evidence
```

Dependencies: CPython, NumPy, SciPy, PyTorch with CPU FP64. The reference deliberately rejects GPU overrides because its fixed-node tensors are CPU, and rejects non-finite/unsupported parameter regimes. The `probability_torch` omitted-tail diagnostic is **not** a bound on Gauss-Legendre quadrature error.

## Explicit remaining blockers (P0–P6 all OPEN)

- **P0:** original financial He–Xiong globally coupled fixed-point/obstacle and low-precision guarantees; dynamic regenerative QVI existence/uniqueness and robust mixed-precision implicit gradients.
- **P1:** heldout, same effective parameters, matched signed local slopes and total compute; prior ordinary-gate superiority and structural rank-one counterexample remain unsolved.
- **P2:** trained autonomous long-horizon multi-hit event dynamics; no future leakage in a trained system; irregular-time Selective Copy/MQAR/joint recall, learned reset causal value, backprop through sampled event times, failure/restart semantics.
- **P3/P4:** actual real text/speech/vision/video encoders and paired heldout cross-modal alignment/semantic/temporal/entity evidence.
- **P5:** fused operator, real device CPU/GPU measurements, p95/p99, peak RSS and physical energy, independent benchmark.
- **P6:** frozen-medium-encoder training, distillation and quality-cost frontier with negative-transfer controls.

**Keep a Draft PR stacked on #498. Do not merge main or enable production; never equate numeric integration with end-to-end model validation.**
