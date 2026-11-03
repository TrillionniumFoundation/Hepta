# HCSN iteration 31 — falsify horizon-calibrated constant hazard as a first-hit surrogate

**Status: P0–P6 OPEN; production activation FALSE.** This report documents a restricted, reproducible **negative** submodel. Nothing here independently validates original He–Xiong Eq 8/11/12/A7, global-domain/QVI, fair P1 FLOP/slope budgets, trained dynamic boundaries or multi-modal hardware quality. Do not merge main, change trust roots, or lower signature requirements.

## Frozen comparison

- Source lineage: Hepta Draft #468 (original HCSN), #481 (regenerative events), #486 (constant-coefficient two-state Markov reset), #512 (physical ZOH hazard clock). The proposed files are additive to #512, not a replacement for #486 or its validated constrained law.
- Ground truth: driftless Brownian state with threshold distance `a=0.4`, volatility `sigma=0.4`; **after each hit reset a distance below the same constant barrier**; new independent Brownian increments by the strong Markov property. Zero refractory, infinite theoretical event budget, no learned weights. Distribution of each cycle time `a*a/(sigma*sigma*Z*Z)`, with `Z~N(0,1)`.
- Exact n-th event CDF: `erfc(n*a/(sigma*sqrt(2*t)))`; independently checked with `scipy.integrate.quad` on the Levy density and three seed groups of 40,000 independent inverse-normal paths.
- Surrogate: #512's unmodified `PhysicalHazardClock` with a constant rate `lambda=-ln(1-P(T_1<=1s))/1s = 0.38171514630212616 /s`. This exactly matches first-event probability at **one frozen calibration horizon, 1s**. Other horizons (`0.25,0.5,4,16s`) and repeated events (`n=2,3`) are out-of-distribution.
- This is **not** a proof all hazard models fail: a correctly calibrated elapsed-age/state-conditional time-varying intensity may match some hitting-time marginals; matching distribution still does not automatically recover realized pathwise crossings or causal event time.

## Exact independent negative results

| Horizon | Event rank | Brownian true CDF | Calibrated ZOH hazard CDF | Error (percentage points) |
|---|---:|---:|---:|---:|
| 1s | 1 | 0.31731051 | 0.31731051 | 0.00 |
| 1s | 2 | 0.04550026 | 0.05671759 | +1.12 |
| 4s | 1 | 0.61707508 | 0.78278347 | +16.57 |
| 4s | 2 | 0.31731051 | 0.45112411 | +13.38 |
| 16s | 1 | 0.80258735 | 0.99777376 | +19.52 |
| 16s | 2 | 0.61707508 | 0.98417715 | +36.71 |
| 16s | 3 | 0.45325470 | 0.94265687 | **+48.94** |

Maximum absolute independent density-quadrature disagreement on 15 (time, event rank) scenarios: `1.11e-16`. Three seeds `(11,23,37)`, 40,000 Levy paths each, maximum absolute Monte Carlo standardized deviation `1.86`. Direct invocation of the **existing** `PhysicalHazardClock` with 1,000 deterministic seeds gives `P(N(16s)>=3) = 0.942` versus independent Poisson `0.9426569` and Brownian `0.4532547`.

## Commands (repo root, where #512 source is available)

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 PYTHONPATH=.
python -m unittest research.hcsn.test_p2_physical_hazard_clock research.hcsn.test_p2_first_hit_renewal_falsification -v
python -m research.hcsn.p2_first_hit_renewal_evidence --output /tmp/hcsn-iteration31-brownian-firsthit.json
python -m research.hcsn.independent_gate --bundle /tmp/hcsn-iteration31-untrusted-empty --strict --output /tmp/hcsn-iteration31-strict.json
# EXPECT: strict gate exit code 2; all P0-P6 OPEN, production_activation=false
```

For the committed original per-seed evidence, decode without altering the JSON bytes:

```bash
base64 -d research/hcsn/gates/2026-11-03-iteration31-brownian-renewal-negative.json.gz.b64 | gzip -d > /tmp/hcsn-iteration31-committed.json
sha256sum /tmp/hcsn-iteration31-committed.json
# EXPECT: 5802b7c99074e5f8f07b4c2aa1e0ab3bca12e2bc0f2fb0158d6dd1f4bceacab1
```

The evidence generator refuses to overwrite an existing output. SHA256 for source files are embedded in the unmodified original JSON, with Python/NumPy/SciPy versions and per-seed observations. No external independent attestation, no true multi-modal pretrained encoders, no GPU energy or long MQAR accuracy was obtained. Existing negative results in P1 and P2 remain unchanged.

**Next necessary experiment:** train a causal elapsed-age/state-conditioned rate or moving first-hit boundary using one task-heldout protocol and measure both sample-grid invariance and event-time calibration, path fidelity, Selective Copy/MQAR multi-seed OOD, matched FLOPs, and tail runtime. Do not equate an accurate Poisson law with first-boundary hitting semantics.
