# HCSN P2 iteration 14: third autonomous event with time-adaptive reset

**Research only: all P0–P6 scientific gates remain OPEN; production disabled.**

## Mathematical increment

An event-time-conditioned reset policy independently draws a mode at the real time of each autonomous crossing of the signed log-margin barrier. Conditional on first and second event times, the third-event finite-horizon probability is a two-dimensional first-hitting-time density integral. The PyTorch FP64 CPU implementation uses nested sin-squared Gauss-Legendre quadrature, positive-refractory feasibility cutoffs and independent coarse/fine refinement checks. This is NOT a general solved He–Xiong nonlinear QVI, not a learned memory network and not a differentiable sample spike path.

## Observed evidence (2026-10-31)

- Added 6 new tests on top of iteration 13, total 15 new adaptive-event tests; reconstructed full local HCSN suite **150/150 passed**. This is not remote GitHub Actions evidence.
- Independent constant-reset reduction: the third hitting law collapses to the weighted stationary first-passage transform at distance x0 + R_i + R_j and time T-2*rho.
- Time-dependent case checked with **180,000** independently sampled exact-time inverse-Gaussian/Wald paths (exploratory 5 standard-error threshold, not preregistered).
- Positive/negative drift: 90 fixed-seed bounded parameter panels passed; max coarse/fine discrepancy **8.500207895334455e-7**.
- Tested case: first-hit probability **0.8259766457159015**, second **0.5854989824012767**, third **0.3396789579843724**. Third discounted event expectation **0.18320320160652365**.
- 13-dimensional signed derivative central finite-difference test passed: max absolute difference **1.710567243407013e-10**.
- Descriptive CPU eager FP64 scalar measurement (100 repeats): second p50 **6.366 ms**, p99 **8.104 ms**; third p50 **17.244 ms**, p99 **20.390 ms**. This is not device energy, multi-neuron throughput or a fused kernel.
- Strict independent gate still rejects with exit **2**; real P0–P6 signatures absent, production_activation=false.

## Reproduction

    python -m pip install -r research/hcsn/requirements.txt
    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
    python -m research.hcsn.independent_gate --bundle research/hcsn --strict

## Remaining blocking work

- P0: full coupled original HX equity/A7 and endogenous regenerative QVI, all admissible domains, stable BF16/FP32 reference.
- P1: rigorous matched-parameter, signed-slope, compute-budget, data and training comparisons demonstrating independent value.
- P2: genuinely learned 3+ state regenerations with content memory; Selective Copy, MQAR, joint recall, irregular-time extrapolation, robust multi-seed BPTT.
- P3: independently trained/evaluated real text/audio/vision/video Encoder baselines.
- P4: multimodal temporal and semantic grounding, missing-modality and negative transfer.
- P5: fused native CPU/GPU, p95/p99, device energy, RSS, production throughput. Current scalar quadrature is too slow for large neuron populations.
- P6: medium Encoder continuous pretraining and preregistered quality–cost frontier.

This incremental PR remains intentionally draft, not merged into main. Source and tests: adaptive_third_hit.py and test_adaptive_third_hit.py, with machine-readable iteration14-evidence.json.
