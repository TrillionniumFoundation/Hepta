# HCSN P2 iteration 28 — trained dynamic-boundary physical-clock falsification

2026-11-02. **P0–P6 OPEN, production activation false.** Additive research-only regression for Draft PR #512. No rewrite of prior evidence, no main merge or signed gate changes.

## Pinned source and scope

- main `125d11c5454835a7df1dc51915fc49901fbede5b`; #468 `00a9dc11714f35866be18cd4fece5ce3addefc4a` (Draft); #481 `407201690a617629255d7f5d0968ce4c544c1b93` (Draft); #486 `1aa8eb5f0efc2661472aa5a11221c07553152a03` (Draft).
- #512 branch `research/hcsn-edge-refractory-negative-20261031-gpt6`, base `research/hcsn-hardforward-ood-falsification-20261031-gpt6` at `2ce3267ca148a6568497cc20b27c09c26058b739`; parent HEAD before this test `f808a8ef85b2e89634f89a20f386ed9031f7d0d8`.
- Retains existing negative P1/P2 observations, including iteration 27's dynamic-boundary deficit against the instantaneous control. This is not a fair matched-compute P1 study, a stochastic QVI or an encoder experiment.

## Testable blocker

The real **trained** P2 dynamic model updates `volatility = 0.9 * volatility + 0.1 * abs(context - previous_level)` once **per token**, with no `dt` factor. The level uses the physical-time exponential `alpha=-expm1(-dt/4)`. Consequently identical constant context over identical physical time can yield different volatility state, threshold, and hard event decision solely from observation frequency.

At each seed 11, 23, 37 retrain the existing published 40-step **query-only** control (no event-label supervision). Hold context at 1 for 4 physical seconds, with 4, 16 or 64 samples; apply the **same** context probe `1-exp(-1)+0.78` at time 4.01 seconds. All outputs and raw trained parameters are in the JSON.

| Sampling | Final level | Volatility | Learned boundary (seed 11) | Probe event (all 3 seeds) |
| --- | ---: | ---: | ---: | --- |
| 4 samples / 4 seconds | 0.63212055 | 0.23780727 | 0.72059745 | true |
| 16 samples / 4 seconds | 0.63212049 | 0.46324083 | 0.84935963 | false |
| 64 samples / 4 seconds | 0.63212061 | 0.43398309 | 0.83186311 | false |

Unlike the original token-rate EMA, an **independent deterministic held-context physical-clock ODE** reference `dL/dt=(1-L)/4`, `dV/dt=(abs(1-L)-V)/tau`, `tau=-1/log(0.9)` has exact semigroup updates and returns volatility `0.2099500481453896` within ~3e-16 under all three samplings. This is a limited clock-consistency reference, not a proposed or accepted HCSN stochastic solution. A held-constant context carries no additional information at intermediate samples; the differing probe decisions expose sampling-frequency dependence of the current trained operator.

The 3 seeds are deterministic paired repetitions, **not** independent training organizations or external statistical acceptance. The probe is a constructed adversarial case, not a claim about full OOD MQAR performance or about actual hidden Brownian first-hit times. Prior negative benchmark results remain unchanged.

## Exact local commands and verified outputs

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. python -m unittest research.hcsn.test_p2_no_event_dynamic_boundary research.hcsn.test_p2_physical_clock_invariance -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. python -m research.hcsn.test_p2_physical_clock_invariance --output research/hcsn/gates/2026-11-02-iteration28-physical-clock-raw.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. python -m research.hcsn.independent_gate --bundle research/hcsn/gates --strict
```

Reconstructed CPU research environment: Python 3.13.5, PyTorch 2.10.0+cpu, NumPy 2.3.5; no CUDA. Combined local tests **12/12 PASS, zero skipped**, generation exit `0`, independent strict gate exit **`2`**, P0–P6 OPEN, `production_activation=false`. This is not full checkout / branch CI, GPU or external independent signature evidence.

- `test_p2_physical_clock_invariance.py` SHA256 `671157d032352d398315e94d50457331798e89d3f48a2bb6975f2aa1f2c83ced`
- `gates/2026-11-02-iteration28-physical-clock-raw.json` SHA256 `5cfee07694cf95e63ced1fd5fe733fb19792eca7907cfcc6e7d8cc7fa6fe1578`
- original `p2_no_event_dynamic_boundary.py` SHA256 `bff9aa7dba1b4b73ae3445fdba39a7ef115e9df4eed47548848be0f6318d23c6`

## Next strict scientific requirements

A candidate fix must replace token-clock accumulation with physically consistent statistics and validate causal stream/chunk equivalence, resampling/OOD, differentiability, actual repeated autonomous event timing, Selective Copy/MQAR and fair matched-budget baselines on unseen seeds. It must retain existing negative results and explicitly measure any lost event precision/recall. All P0–P6 remain OPEN until fully independently evaluated and externally attested; no main merge, signature relaxation or production activation.
