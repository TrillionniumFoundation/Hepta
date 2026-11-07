# HCSN P2 Iteration 11 — stationary regenerative first-hit spike counts (research-only)

Date: 2026-10-31. Intended base: `TrillionniumFoundation/Hepta` Draft PR #468, branch `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`, exact inspected HEAD `129a65c9235f41a4a0be9e740551c90b21971d8a`.

**P0–P6 SCIENTIFIC ACCEPTANCE OPEN; production disabled.** This work does not close endogenous dynamic free-boundary modeling or downstream neural learning.

## What is actually established

A scalar signed log-margin GBM `X_t > 0` follows `dX = mu dt + sigma dW`. On its **first** barrier hit it instantaneously resets to a strictly positive constant `R` and restarts with the same coefficients. Strong Markov and Brownian spatial homogeneity imply that the nth event time has the law of a first hit from distance `x0+(n-1)R`. Consequently,

- `P[N(T)>=n] = F(T, x0+(n-1)R, mu, sigma)`.
- `P[N(T)=0] = 1-F_1`, `P[N(T)=k] = F_k-F_{k+1}` for `k>=1`.
- The **explicit right-censored** residual is `P[N(T)>K] = F_{K+1}`, never silently dropped or assigned to event count `K`.
- Sum of discounted first `K` event rewards is `sum_{n=1}^K G(T, x0+(n-1)R, mu, sigma, lambda)`. These are exact *restricted-model* expectations, not full-network energy or utility.

The closed first-passage operators are inherited unchanged from `moving_boundary_first_passage.py`. A bounded scalar CPU/FP64 interface refuses nonfinite, invalid or unsupported shapes and unbounded event tails when a caller requests a maximum censoring threshold. Gradients can be propagated through scalar expected counts/rewards for **positive discount**; a zero-discount gradient is explicitly rejected because the underlying first-hit branch does not certify `dG/dlambda` at zero.

## Actual local execution

- `9/9` new method-level tests passed (including 100 fixed-seed bounded parameter panels, independent first-hit density integrals, positive-drift defective law, rejection and gradient finite differences).
- The locally reconstructed HCSN research suite plus this increment passed **124/124 tests**, Python 3.13 / PyTorch 2.10 CPU. This does **not** claim a complete remote checkout, GitHub Actions run, or an independent formal proof.
- Independent inverse-Gaussian/Levy renewal Monte Carlo sampled **360,000 paths**, three drift regimes (`-.25`, `0`, `+.18`), seeds `202601, 202602, 202603`, 120,000 each. The largest absolute descriptive standardized count deviation was **2.394**, and discounted-reward standardized deviation **0.975**. These are exploratory descriptive standard errors, **not preregistered statistical acceptance**.
- Evidence: `research/hcsn/gates/2026-10-31-iteration11-renewal-evidence.json`; full count histogram and censored overflow retained for all regimes.

## Reproduce from repository root

```bash
python -m pip install -r research/hcsn/requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m unittest discover -s research/hcsn -p 'test_*.py' -q
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  python -m research.hcsn.p2_stochastic_renewal_evidence \
  --output /tmp/hcsn-iteration11-renewal.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

The last line **must continue to fail closed** until genuine independent P0–P6 signatures and preregistered evidence are available; neither this script nor these unit tests bypass the scientific gate.

## Provenance and scope

Source SHA256 from actual local execution:

- `stochastic_regenerative_counts.py`: `41c69d85e11aa85a87ffadca981b75c97ca73200168f7c3c28ba871cdbce5a60`
- `test_stochastic_regenerative_counts.py`: `62d71652aa2abeebcc82004b807b74a379102690fe97ca7b8a8920ad11592ece`
- inherited unchanged `moving_boundary_first_passage.py`: `137f4a8338bd968f9ac6a6400b75873190497f3940948988511fa7498f7303ef`
- JSON evidence SHA256: `2ba045bee2229e83d88bb6d5300699d6df77803d9246210a8474c2f4bbcb49d2`

Scientific limitations: constant scalar coefficients, stationary boundary, fixed constant reset margin, no refractory cost, no changing input-dependent reset, no multi-neuron interactions or recurrent content memory, no train/inference event-count derivative, no PyTorch GPU / FP32 / BF16 certification, no real Encoder benchmark. The code reports scientific admission **false**. The original He–Xiong finite-maturity coupled equilibrium is neither changed nor certified here.

## Still-open gates

- **P0 OPEN:** global coupled financial HX, discontinuous moving free-boundary QVI, interval bounds, native low-precision/GPU.
- **P1 OPEN:** local shape + signed-slope + resource-matched positive causal gains; existing negative evidence retained.
- **P2 OPEN:** learned autonomous multi-reset sequence memory (Selective Copy, MQAR, joint recall), long-horizon BPTT through event-count changes, OOD and multi-seed acceptance; this iteration **only** validates an exact stationary reset-count submodel.
- **P3/P4 OPEN:** frozen real text, audio, image, video encoders with heldout multimodal alignment and missing-modality tests.
- **P5 OPEN:** native fused CPU/GPU, device Joules, end-to-end p95/p99/RSS/throughput.
- **P6 OPEN:** medium encoder, continuous pretraining/distillation, frozen quality-cost frontier.

**Merge policy:** research-only PR, do not merge to `main`, do not set `production_activation=true` or any scientific gate to PASS.
