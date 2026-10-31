# HCSN P2 iteration 13: causal time-adaptive reset, research only

**Scientific gates P0–P6 remain OPEN. Production activation = false.** This increment adds a bounded differentiable second-spike expectation with a reset policy chosen from the real first-event time. It is NOT the original coupled He–Xiong A7 endogenous QVI, a differentiation of sampled spikes, or trained sequence memory.

## New research implementation

- First log-margin hit by drifted Brownian motion; Bernoulli reset mode depends causally on event time through a sigmoid.
- Mode-specific positive reset margins vary with event time; deterministic refractory period varies with event time.
- The second-hit probability and discounted transform use a conditional first-passage integral. Gauss-Legendre quadrature uses a sin-squared map concentrating nodes at both endpoints and an exact time-dependent feasibility cutoff.
- Differentiable interior with FP64 CPU; invalid shapes, nonfinite values, uncertified discount gradient and unconverged quadrature fail closed.
- Separate SciPy double-density integration, NumPy inverse-Gaussian event-time simulation, stationary renewal reduction, 13-dimensional gradient finite differences and 125 fixed-seed panels.

## Reproduction from repository root

    python -m pip install -r research/hcsn/requirements.txt
    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
    python -m research.hcsn.independent_gate --bundle research/hcsn --strict

## Observed local evidence

- New tests **9/9** and reconstructed complete local research suite **144/144** passed; no remote workflow run asserted.
- Seed 1337 bounded parameter panel **125/125**; max coarse/fine quadrature discrepancy **1.2542881178134735e-9**, not a certified uniform bound.
- Tested panel first hit probability **0.8259766457159015**; second **0.5854989824012767**; discounted second **0.36853759407929576**.
- Independent double-density integral second probability **0.5854989824013115**, discounted second **0.36853759407931025**; absolute discrepancies **3.475e-14** / **1.449e-14**.
- Monte Carlo: 180,000 independent NumPy Wald paths; exploratory five-standard-error limits met, not preregistered scientific acceptance.
- Max signed autodiff vs central finite-difference difference across 13 parameters **2.865530035478514e-10**.
- Stationary-reset ablation differed by **+0.008612957083904083** second-event probability. Not a neural accuracy gain.
- Strict external independent-signature gate exits **2**: full_closure=false, production_activation=false.
- PyTorch 2.10 CPU, SciPy 1.17, NumPy 2.3.5, no GPU.

## All remaining scientific blockers

| Stage | Outstanding evidence |
|---|---|
| P0 OPEN | Full original HX coupled A7/equity and endogenous QVI, full admissible domain, low-precision |
| P1 OPEN | Matched parameters/signed local slopes/FLOPs/data/training with independent positive gain |
| P2 OPEN | Learned autonomous 3+ resets, Selective Copy, MQAR, long-horizon BPTT and multi-seed OOD |
| P3 OPEN | Held-out pretrained text/audio/image/video Encoder baselines |
| P4 OPEN | Multimodal temporal alignment, entity binding, missing-modality robustness, negative transfer |
| P5 OPEN | Native fused CPU/GPU, whole-model p95/p99, RSS and device Joules |
| P6 OPEN | Medium Encoder pretraining, distillation, preregistered quality-cost frontier |

No main merge, scientific admission, or deployment. Stacked research PR requires independent review before promotion.
