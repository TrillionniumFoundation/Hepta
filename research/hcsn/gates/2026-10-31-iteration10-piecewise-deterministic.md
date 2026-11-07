# HCSN P0/P2 gate iteration 10 — deterministic nonstationary first passage (2026-10-31)

**Strict verdict: all scientific P0–P6 gates OPEN; production_activation=false.** Research-only CPU numerical tool, not original He--Xiong A7 pricing, learned spiking advantage, or a globally certified time-varying QVI.

## Implemented

- `research/hcsn/piecewise_boundary_quadrature.py`: first-hit probability F and discounted first-hit value G for a positive log margin X(t) with piecewise *affine log boundary*, constant drift and sigma.
- Each interval uses the **killed Brownian transition kernel** `Normal(y; x+(drift-slope)*dt, sigma^2*dt) * [-expm1(-2*x*y/(sigma^2*dt))]`, then integrates surviving mass over positive states using two Gauss--Legendre orders (96, 160). Interval hitting expectation uses existing exact affine first-passage kernel; all hitting events are counted only at the *first* contact.
- Static integration upper bound `x_max` is not differentiated; a summed unrestricted Gaussian tail controls probability lost beyond that bound (<=1e-10), independent quadrature-order comparison checks numerical refinement, and survival mass checks conservation. All failures are explicit. No claimed rigorous spatial quadrature truncation proof or FP32/GPU guarantee.
- Autograd supported only within the fixed-segment differentiable interior. Hard event-count transitions remain nondifferentiable.
- `research/hcsn/test_piecewise_boundary_quadrature.py` includes one-segment analytic, two-segment independent `scipy.integrate.quad`, Brownian-bridge MC, six tensor groups / eight signed derivative components vs centered finite differences, segmentation invariance, 40 deterministic 3-segment panels, malformed/truncation inputs.

## Exact local evidence (CPU PyTorch 2.10)

`OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q`

- **115 tests passed** in 6.308 s in a local reconstructed research suite, including the 7 newly added tests. Not GitHub CI; the entire remote branch and original HX model were not independently re-audited by this new iteration.
- 40 heldout fixed-seed panels: maximum coarse/fine difference **4.207745263329343e-14**, maximum first-hit + survivor probability mass error **6.927791673660977e-14**, maximum computed unrestricted tail bound **5.522404805253399e-14**. These are *numerical diagnostics*, not formally proven global discretization error upper bounds.
- Eight signed autograd vs central-difference derivatives: maximum absolute discrepancy **7.703505611189598e-10** at a fixed interior parameter setting.
- Two 0.8-duration segments, x0=0.22, drift=0, sigma=0.26, lambda=0.08, identical initial/final boundary: `[+0.45,-0.45]` gives **F=0.8700345701057436**, G=0.8447904299879757; `[-0.45,+0.45]` gives **F=0.32193047889482074**, G=0.29320619486691574. F difference **0.5481040912109229**. Independent 140k-path Brownian-bridge MC per path gives F 0.8698357 / 0.3198357 (0.22 / 1.68 observed standard errors). This demonstrates *history dependence in a model*, not neural-task benefit.
- Remote source blob SHA verified against executed local bytes: module `2e110a844dda06122fef920edf2612764d12ab4e`, tests `62a4ab418b9e1810a453b8e90097de1cbfffeae1`.

## Reproduce the new tests

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_piecewise_boundary_quadrature.py' -v
```

The existing `moving_boundary_first_passage.py` supplies the affine finite-horizon F/G reference and separate Brownian-bridge simulation. No secret data, external downloads, or GPU required.

## Remaining fail-closed blockers

- **P0**: original HX full physical/admissibility domain; independent high-precision proof and low-precision error bounds; endogenous time-varying/fully nonlocal QVI coupling, independent solver and evidence trust-root certification.
- **P1**: preregistered heldout quality gain over *ordinary* gates with equal active parameters, signed local slopes, FLOPs and wall-clock; current ordinary-gate baselines remain stronger.
- **P2**: autonomous multi-event trained long-horizon recall, first-event-time gradient vs BPTT, independent reset recovery; this numerical first-hit *probability* is not a trained spiking memory network.
- **P3/P4**: real pretrained frozen text/audio/vision/video encoders, aligned heldout tasks and OOD/missing-modality negative-transfer controls.
- **P5**: fused GPU/CPU operators, end-to-end encoder throughput, device energy, memory and p99 resource envelope; O(Nseg*ngrid^2) reference solver is not a production per-neuron activation.
- **P6**: medium-scale pretrained encoder and frozen-budget quality-cost frontier.

**Do not promote, merge to main, or enable production from this research-only numerical checkpoint.**
