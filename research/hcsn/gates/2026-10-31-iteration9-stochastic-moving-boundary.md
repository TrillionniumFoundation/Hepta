# HCSN P0–P6 research checkpoint — Iteration 9: stochastic moving boundaries

Date: 2026-10-31. Repository: `TrillionniumFoundation/Hepta`.
Branch: `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`.
Draft PR: https://github.com/TrillionniumFoundation/Hepta/pull/468.

**All P0–P6 SCIENTIFIC / PRODUCTION gates remain OPEN. Production activation stays false.** The new work proves no improved downstream task quality, and it is neither the full original He–Xiong equity solution nor a general time-varying QVI.

## New verified mathematical subproblem

For a constant-volatility log state with drift `nu` and a moving affine log free boundary `b(t)=b0+gamma*t`, the signed log margin is `X(t)=x+(nu-gamma)*t+sigma*W(t)`. For the first hit `tau=inf{t:X(t)<=0}`, the reference implements **finite-horizon** `F=Pr(tau<=T)` and `G=E[exp(-lambda*tau)*1(tau<=T)]` in closed form, FP64 PyTorch, with autograd on interior smooth regions.

- A **different numerical implementation**, the hitting-time density integrated after the independent change of variables `u=x/(sigma*sqrt(t))`, checks F and G without using the CDF solution: 96 deterministic panels, maximum absolute error **4.440892098500626e-16**.
- Six signed autograd derivatives of G were independently checked with density-based centered differences: maximum discrepancy **1.970144491991732e-9**.
- Exact-time inverse-Gaussian/Levy first-passage Monte Carlo for **420,000 independent paths** across negative/zero/positive relative drifts: all 6 normalized differences below **2.79 standard errors** (exploratory, not preregistered).
- Conditional Brownian-bridge hit simulation for 1/3/12 segments, **450,000 sampled paths**, recovered the constant-slope analytic hitting probability; normalized discrepancies below **1.79 standard errors**. For genuinely piecewise moving boundaries with identical endpoints, early-high vs late-high profiles produced hit rates `0.869036` versus `0.320900` under separate fixed-seed 250k-path Monte Carlo runs. Hence boundary trajectory, not only terminal value, matters.
- Fixed actual FP64 autograd bug at `nu-gamma=0, lambda=0`: guarding `sqrt(0)` *after* sqrt caused NaN propagation through an unused branch; guard the radicand *before* sqrt. Added direct gradient regression and fail-closed numeric domain checks.
- **Input quantization only** (256 deterministic panels; FP64 special-function kernel still used): max absolute deviations `2.7372053512664252e-8` for FP32-rounded inputs, `0.0020527097194489308` for BF16-rounded inputs. NOT GPU/BF16 arithmetic certification.
- Feature-only torch CPU 2048-element batch p50/p99: **0.540/0.983 ms**, 120 iterations, one thread. NOT integrated head, GPU, device power or total encoder latency.

## Source provenance and rerun

The three files below were source-identical (Git blob SHA1 matched) after connector delivery:

- `research/hcsn/moving_boundary_first_passage.py` — blob `0d724fc1af6c5fc762a16882953c63e26ea4fabc`.
- `research/hcsn/test_moving_boundary_first_passage.py` — blob `99ad7d486bdd0c51322e8aefcc63a77a724b029c`.
- `research/hcsn/p2_affine_stochastic_evidence.py` — blob `315fc689169e158dd03c09c007dadbd4877aee6e`.

Full raw evidence file `ITERATION9_STOCHASTIC_AFFINE_EVIDENCE.json` SHA256: `3f71b30988194a9279d493fb5e6c56e498d429b343ff37ac0ac3041bbcf5d581` (generated with fixed seeds; per-run CPU timings may vary). Full JSON and independent research package are available in the accompanying conversation artifact, and the generator regenerates it.

From repository root:

```bash
python -m pip install -r research/hcsn/requirements.txt
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m research.hcsn.p2_affine_stochastic_evidence --output /tmp/hcsn-iteration9.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

In local CPU 3.13.5 PyTorch 2.10.0+cpu research bundle: **108/108 unit tests passed**. Strict scientific gate deliberately **exited 2** (no externally controlled trust root or complete independently reviewed scientific evidence). This does NOT claim the remote GitHub CI has passed, nor that scientific P0/P2 is closed.

## Blockers not hidden by new tests

- **P0 OPEN:** original coupled He–Xiong A7/rollover solution global parameter domain; dynamic stochastic QVI beyond affine-boundary first hitting; full FP32/BF16 kernel arithmetic and CPU/GPU parity.
- **P1 OPEN:** shape/signed-slope/parameter/FLOP matched independent gain over strong ordinary gates. Existing local ordinary gating baselines outperform HCSN on primary synthetic decision tasks.
- **P2 OPEN:** learned, autonomous, multi-reset long-horizon Selective Copy/MQAR/joint retrieval across many seeds, gradient behavior across event-count changes and train/inference equivalence.
- **P3 OPEN:** real frozen text/audio/vision/video encoders; Transformer/Mamba/SpikingSSM matched controlled generalization.
- **P4 OPEN:** real heldout cross-modal entity and time alignment, missing modality and negative transfer.
- **P5 OPEN:** GPU fused kernel, energy joules, integrated throughput/RSS/p95/p99 and BF16 execution.
- **P6 OPEN:** medium encoder training, distillation, continued pretraining and quality-cost frontier.

Independent scientific attestation and honest failure semantics remain prerequisites; the draft PR must not be merged into production until evidence closes them.
