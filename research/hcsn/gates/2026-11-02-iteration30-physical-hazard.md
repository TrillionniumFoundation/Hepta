# HCSN P2 iteration 30: causal physical-time hazard event clock

**2026-11-02 (America/New_York). Research only. P0-P6 OPEN, strict gate exit code 2, production_activation=false.**

## Pinned GitHub state before first commit

- main: `125d11c5454835a7df1dc51915fc49901fbede5b` (unchanged).
- original Draft #468: `00a9dc11714f35866be18cd4fece5ce3addefc4a`, base main.
- regenerative Draft #481: `407201690a617629255d7f5d0968ce4c544c1b93`, base `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`.
- Markov Draft #486: `1aa8eb5f0efc2661472aa5a11221c07553152a03`, base `research/hcsn-stochastic-renewal-20261031-gpt6`.
- Draft #512 pre-commit HEAD: `47b1ef634aa2f4016021f33a35376e1192da5878`; base `research/hcsn-hardforward-ood-falsification-20261031-gpt6`.
- Related open HCSN PR #463, #483, #487, #492, #498, #500, #503, #505, #509, #511, #513, #526, #527 were inspected for status, HEAD/base, changed paths. This patch uses four new additive paths only. Other branches untouched.

## Motivation and mathematically limited result

Iteration29 repaired the deterministic volatility state clock but the *trained* threshold detector still emitted [1,6,25] or [1,6,26] events as the same four-second held trajectory was sampled 4/16/64 times. Here a **distinct, untrained control model** addresses a necessary physical-time consistency condition. A right-continuous nonnegative intensity `lambda(t)` is held from an observed interval start; the compensator increments by `lambda*dt`. An event occurs when the integrated active compensator crosses an Exp(1) threshold; with physical refractory r, no compensator accumulates before event_time+r. Draws are consumed only on actual events, so inserting redundant samples on an identical intensity path cannot change event times. The implementation validates time/rate inputs and stages state changes atomically to reject over-budget intervals without state mutation.

This **is an inhomogeneous Poisson/renewal control, not an original He-Xiong Eq8/11/12/A7 first-hit solver, continuous Brownian bridge, learned task-aware boundary, or an observed HCSN improvement**. A softplus context-to-rate map is included but its weights are not fitted. No evaluation-time future observations are used.

## Independent numerical reference and negative control

A *separate* SciPy QUAD + Brent root inversion independently reconstructs first event times for five RNG seeds, variable piecewise intensity knots `[0,1,2.5,4]` seconds, and refractory 0 or 0.31 seconds. There are ten seed-by-refractory cases, tested on rate-path subdivisions 1/4/16/64. Largest event-time error versus independent reference: **3.1086244689504383e-15 s**; largest grid refinement error: **1.4654943925052066e-14 s**.

Same four-second held rate 0.7, with physical refractory 0.2: seeds 11/23/37 now emit counts [2,2,2], [1,1,1], [3,3,3] on 4/16/64 observations, respectively. This is a **different stochastic event policy** and its counts must not be compared as an accuracy gain to the iteration29 trained policy. The per-token Bernoulli p=0.2 null control has expected counts 0.8/3.2/12.8 under the same resampling and is knowingly non-invariant.

For 2000 independent seeds, no-refractory theoretical Poisson mean 3.3, empirical mean 3.3665, population variance 3.26517775, and count>=4 probability 0.437 versus Poisson 0.4196618025. This is a finite-seed plausibility check, not an independent scientific gate acceptance.

## Actual execution

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. python -m unittest research.hcsn.test_p2_physical_hazard_clock -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. python -m research.hcsn.p2_physical_hazard_evidence --output /tmp/hcsn-iteration30-recomputed.json
sha256sum /tmp/hcsn-iteration30-recomputed.json research/hcsn/gates/2026-11-02-iteration30-physical-hazard-raw.json
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONPATH=. python -m research.hcsn.independent_gate --bundle research/hcsn/gates --strict
```

CPU minimal reconstruction (not complete remote checkout): **12/12 unit tests passed, zero skipped.** Strict independent gate actually exited **2** because there is no external trust root; every P0-P6 verdict OPEN. GitHub combined-status and PR workflow-run queries on the predecessor SHA returned no confirmed runs; **not CI PASS**.

SHA256 sources:
- physical clock: `b5bc94f23288fb10aa44442452f2ef78ad8c3181e77d0cf2a5ddcc41551da15f`
- 12 tests: `7b2b0a9fc2a150131946b0ee0886aac3d9a96d5e0e6c213fb7cef3c9c40cf77b`
- evidence generator: `6e3718d2afc6a2f13d2c42caf751410ded7d82bf40f97fa2c2d92c2d431252fd`

Previous negative results MUST remain: query-only trained dynamic clock loses OOD hard MQAR to instantaneous (93.02% vs 95.52% in iteration29), P1 slope/parameter/FLOP budgets still unmatched, and trained real-event precision/recall not established. P0 complete original HX/A7 all-domain, P3/P4 four pretrained encoders + heldout, P5 real hardware GPU energy/p99, and P6 model frontier **remain OPEN**. No changes to main, release gates, signatures or production activation.
