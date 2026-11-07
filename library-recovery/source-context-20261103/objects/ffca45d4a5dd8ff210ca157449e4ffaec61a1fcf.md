# Hepta Continuous Spiking Network — P0–P6 research checkpoint, iterations 7–8

Date: 2026-10-31. Research-only, CPU-only. **P0–P6 scientific gates OPEN and production disabled.**

Repository: `TrillionniumFoundation/Hepta`; draft PR: https://github.com/TrillionniumFoundation/Hepta/pull/468; research branch: `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`. Verified branch head after the two additions: `3b336152b4e5bb1e174bc070cd1d02d66fc75350` (may advance later). No merge.

## New bounded P0 reference: original HX equity Eq11

`hx_equity_fd_independent.py` implements an independent monotone finite-difference log-GBM solver using Eq8 bond valuation as source, without using the published A7 formula, Eq12 algebraic boundary, or the existing equity Green evaluator in the FD solve. `solve_boundary_fd` recovers a numerical smooth-pasting root via two independent FD solves, then tests mesh convergence and Richardson extrapolation.

Six bounded parameter panels (including `xi*k=0`), three FD mesh sizes (800/1600/3200), six positive log-margin equity values per panel. Max scaled FD-vs-Green equity difference: `2.6263308181517786e-4`. Max relative Richardson-vs-Eq12 boundary difference: `1.7908688396683914e-6`. Results in `ITERATION7_EQUITY_FD_EVIDENCE.json`; source and evidence command in `p0_equity_fd_evidence.py`. NOT an independently preregistered or all-domain proof; the direct A7 formula near zero liquidity remains singular and was explicitly excluded in that panel.

Remote introducing commit `cf10090a0acf72d00d830b2b08bf24e7ef34285b`; independent gate report: `research/hcsn/gates/2026-10-31-iteration7-equity-fd.md`.

## New bounded P2 mechanism: independently moving boundary and exact event timing

`moving_boundary_events.py` permits separate affine motion for log state and log free boundary on irregular time partitions, with endogenous contact/reset events, negative or zero relative depletion, and continuous autograd inside fixed-event-count regions. `test_moving_boundary_events.py` adds seven tests; `p2_moving_boundary_evidence.py` produces 128 reproducible random panels.

Valid fixed-event-count panels: 115; 13 excluded for proximity to event-interval transition; signed auto-diff versus centered FD gradient components: 1,380; maximum absolute discrepancy `2.4505295570520502e-09`. Results in `ITERATION8_MOVING_BOUNDARY_EVIDENCE.json`. **Event-count surfaces are discontinuous and not differentiated.** This is a deterministic event reference, NOT long-memory learning evidence, an exact stochastic QVI, or a model-quality gain.

Remote introducing commit `4e41d767a79c59737bf7ce1c4d64c67a9e3dcdad`; report: `research/hcsn/gates/2026-10-31-iteration8-moving-boundary.md`.

## Fresh execution and fail-closed gate

From the directory containing `hcsn_round5_20261031`:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s hcsn_round5_20261031 -p 'test_*.py' -q
python -m hcsn_round5_20261031.independent_gate --bundle hcsn_round5_20261031 --strict
python -m hcsn_round5_20261031.p0_equity_fd_evidence --output /tmp/hcsn_new_fd.json
python -m hcsn_round5_20261031.p2_moving_boundary_evidence --output /tmp/hcsn_new_events.json
```

Observed CPU environment: Python 3.13.5, torch 2.10.0+cpu, numpy 2.3.5, scipy 1.17.0. **96/96 tests pass**. Independent scientific release gate exit code **2** due missing external independently managed trust root and missing scientifically approved P0–P6 evidence. That is expected protection, not test suite failure. No production activation.

## Scientific blocker ledger

| Phase | Status | Essential absent evidence |
| --- | --- | --- |
| P0 | OPEN | Global HX coupled solution certified over admissible domain, singularity, BF16/FP32/derivatives, time-dependent QVI and target-hardware parity |
| P1 | OPEN | Independently heldout, equal-parameter, signed-slope and compute-matched positive gain vs strong ordinary gates; existing toy null wins |
| P2 | OPEN | Learned long-context selective copy/MQAR/joint recall under many seeds, moving-boundary parameterization with event-count transitions and train/inference equivalence |
| P3 | OPEN | Genuine pretrained text/speech/vision/video encoders, Transformer/Mamba/SpikingSSM matched comparison |
| P4 | OPEN | Heldout crossmodal time/entity alignment, missing-modality retrieval and OOD negative-transfer evaluation |
| P5 | OPEN | Real GPU fused kernels, device joules, full-model throughput/p95/p99/RSS and quantized equivalence |
| P6 | OPEN | Medium-sized encoder training, continued pretraining, distillation and preregistered quality-cost frontier |

This package does not include actual pretrained multimodal weights or real GPU measurements. No phase should be marked CLOSED solely because these engineering tests pass.
