# HCSN research — next gate sweep (2026-10-31)

**Fail closed:** P0–P6 are *scientifically OPEN*. Do not enable a production feature or merge research as a model-quality claim.

## Verified local experiment checkpoint

- Python 3.13.5, Torch 2.10 CPU, NumPy/SciPy/mpmath. Local source package unit tests: **60/60 PASS** (not a remote CI result).
- P0: 84 bounded He–Xiong param combinations checked against independent smooth-fit integral root and equity Green solution; max relative boundary discrepancy 1.18e-11, max A7/Green relative discrepancy 2.92e-10. Ten zero-hazard cases need the MP derivative limit, addressed by research-only `hx_a7_mp_regularized.py`; wide-domain FP32/BF16 safety is not proven. Independent FD policy iteration for fixed/conditioned regenerative QVI checks numerical complementarity.
- P1: three seeds and local signed-Jacobian tangent control at **one** anchor, equal 161 trainables, same training updates. No global slope/FLOP match. Original ordinary two-gate control remains a stronger null on the earlier heldout task; superiority NOT established.
- P2: 3-seed dual-key joint recall after two externally signaled boundary reset events, 125 updates each. On length-48 irregular sequences: analytic 50.17%, ordinary 48.87%, reset-GRU 50.87%. This is at chance and does NOT close the memory gate. A reset marker intentionally raises the boundary; autonomous endogenous spike timing is **not demonstrated**.
- P5: single-thread CPU eager full recurrent forward, B=128/T=24: analytic 7.53ms p50, ordinary 7.76ms, GRU 1.57ms. These are NOT energy measurements, target hardware benchmarks, or matched-capability throughput. A 5-term CDF approximation showed 7.45e-8 max absolute error on [-8,8] and remains unintegrated.
- P3/P4: no frozen real text/audio/image/video encoders, external heldout multimodal data, Transformer/Mamba/SpikingSSM controls, or negative-transfer result.
- P6: no medium-size encoder, continued pretraining, or frozen quality-cost frontier.

## Required next pass criteria

1. P0: explicit global admissibility/negative-tail contract; independent high-precision error envelopes and gradient wrt boundary/parameters; complete dynamic-context QVI tests.
2. P1: **global** local signed-slope + FLOPs wall time calibration, preregistered paired heldout confidence bounds, positive net effect versus ordinary control.
3. P2: joint/MQAR long-context accuracy substantially above chance; autonomous multiple learned resets; BPTT vs event-time gradients, no leakage.
4. P3/P4: reproducible real frozen encoder comparisons on text/audio/image/video, missing modalities and cross-modal alignment, independently heldout negative transfer.
5. P5: target CPU/GPU, fused kernel, end-to-end energy, memory and tail latency at relevant context length.
6. P6: longer-context and medium-size trained encoder on same frozen budget.

This branch contains **research-only original HX/P0/QVI references and the regularized A7 zero-hazard patch**; the broader local exploratory training/performance bundle has not been promoted into the production repository. No external CI is claimed by this report.

Paper: He & Xiong (2012), *Journal of Finance*, Eq. 8, 11, 12, A7. https://www.princeton.edu/~wxiong/papers/rollover.pdf
