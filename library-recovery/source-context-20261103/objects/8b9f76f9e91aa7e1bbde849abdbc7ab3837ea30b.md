# HCSN iteration 10 — actual status and reproduction (2026-10-31)

Research PR: https://github.com/TrillionniumFoundation/Hepta/pull/468
Branch: `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`
Final remote evidence commit: `819e33f691e9a3a255a74a6088789512e65ba951`

## New work, verified local

- `piecewise_boundary_quadrature.py`: deterministic FP64 CPU Gauss–Legendre killed-diffusion composition, with F/G and differentiable fixed-topology path.
- `test_piecewise_boundary_quadrature.py`: 7 tests including independent adaptive integral, Brownian bridge MC, gradients, conservation, refinement, 40 randomized 3-segment panels, and fail-closed inputs.
- Local research integration mirror: 115 tests PASS, elapsed 6.308s, GitHub CI not claimed.
- Both source files were fetched back via GitHub and remote Git blob SHA matched locally executed files exactly.
- Raw numbers: `ITERATION10_PIECEWISE_DETERMINISTIC_EVIDENCE.json`.

## Scientific gate status

**P0, P1, P2, P3, P4, P5, P6 all OPEN.** The new F/G operator is an *approximate, bounded* solution for nonstationary piecewise-affine Brownian first hitting, not original HX Eq A7 / full dynamic endogenous QVI / scientifically validated HCSN neuron / real encoder model.

Production activation remains prohibited; prior ordinary two-gate and GRU baselines were stronger in several existing tasks. Full multimodal pretrained models, GPU wattmeter, scaling, quantized native kernels and externally attested scientific evidence remain absent.

## Reproduce

From this zip's parent directory:

```sh
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s hcsn_iteration10 -p 'test_*.py' -v
```

This package runs the 7 new deterministic tests; it carries the earlier first-passage implementation as a dependency but not its separate tests. The 115-test integration includes the wider local research mirror and is not bundled in full here. Use main PR branch `research/hcsn/` for wider reproduction.

## Next strict gate

1. Original HX full-domain independent solver, endogenous state-dependent moving QVI coupling and high-precision/FP32/BF16 error envelopes.
2. P1 preregistered matched-parameter and matched-signed-slope/FLOP controls and OOD positive net benefit vs ordinary gates.
3. P2 autonomous learned repeated event timing and long-horizon MQAR under matched training budget.
4. P3/P4 real frozen pretrained text/audio/image/video + cross-modal heldout fairness, negative transfer.
5. P5/P6 fused hardware kernels, complete power/throughput/RSS/p99 and medium-size encoder training.
