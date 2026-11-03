# HCSN Iteration 33 — two-mode Markov defective first-hit negative control

**Research ONLY — P0–P6 OPEN — DENY_ALL — production_activation=false.**
Prepared against Draft #512 expected parent `fc8dce73a35fce8c5cec4f2316997e339b951925`; base `research/hcsn-hardforward-ood-falsification-20261031-gpt6` (`2ce3267ca148a6568497cc20b27c09c26058b739`). Foundation Draft #468 `00a9dc11714f35866be18cd4fece5ce3addefc4a`, #481 `407201690a617629255d7f5d0968ce4c544c1b93`, #486 `1aa8eb5f0efc2661472aa5a11221c07553152a03` remain OPEN.

## New falsifiable statement

Iteration 32 established a defective Brownian first-hit clock for one state. Here two states use **state-dependent drift, diffusion, barrier distance and outgoing physical refractory**, with an independent Markov transition after each actual hit. Let `q_i = min(1, exp(2*mu_i*a_i/sigma_i²))`. Then `Pr(N(∞)>=n) = pi Dq (P Dq)^(n-1) 1`. The Laplace transform of the (possibly infinite) n-th event time is `pi Dphi(s) [Dexp(-s*r) P Dphi(s)]^(n-1) 1`, with `phi_i(s)=exp[a_i*(mu_i-sqrt(mu_i²+2*sigma_i²*s))/sigma_i²]`. These are exact ONLY for independent mode-dependent Brownian excursions with event-driven mode jumps, not for state-changing-between-events or learned endogenous barriers. An ever-not-hitting excursion stops the event series permanently. The clock samples its next waiting time at regeneration, not per observation.

Fixed audit: `a=(0.4,0.4)`, `mu=(-0.4,+0.12)`, `sigma=(0.4,0.4)`, `r=(0.1,0.2) seconds`, `pi=(0.5,0.5)`. Compare a persistent transition `[[.95,.05],[.05,.95]]` with alternating `[[.05,.95],[.95,.05]]`, both with the same initial mode distribution, same per-mode first-hit laws and same one-event probability.

| Statistic | Persistent | Alternating |
|---|---:|---:|
| eventual first event | 0.56766764 | 0.56766764 |
| eventual second event | 0.49046669 | 0.15402641 |
| eventual third event | 0.45985902 | 0.07788650 |
| second event by 8s (independent flux integral) | 0.36984021 | 0.13139483 |
| eventual 100th event | 3.30475832e-03 | 8.21543388e-43 |

**Observed negative control:** merely holding averaged per-state q fixed does not preserve the third-event probability: persistence changes it by **38.197 percentage points**. A scalar i.i.d. averaged-q replacement predicts `q_bar³=0.18292894`, wrong for both.

## Independent, constrained numerical evidence

- Full enumeration of `2^n` mode sequences for n=1..7, four Laplace rates, two P matrices (56 comparisons): maximum absolute discrepancy **3.33e-16**.
- First-event CDF cross-checked with separate reflection-principle normal CDF and independently integrated first-hit flux over 16 scenarios.
- Two-event 8-second probability from separate SciPy flux × next-CDF quadrature, compared with independent seeded NumPy Wald plus survival Bernoulli Monte Carlo.
- Six independent seed/matrix panels × 45,000 paths (270,000 trajectories) with event ranks 1–3, plus raw integer event counts in JSON. Max standardized deviation for eventual hits was **1.581 standard errors**.
- 6 fixed-seed refinement comparisons: a 16s advance vs 64 intervals yielded identical `(physical_event_time, mode)` and enforced outgoing-state refractory. **Distributional scheduler check, not pathwise Brownian event reconstruction**.
- **38/38** combined local tests with prior #30–#32 source, including 10 new tests, passed. `combined_tests.log` SHA256 `47c17b1f312c05ff87c49128d6fd6409a434cac37d10d412422fa79488195a8a`.
- Exact fail-closed independent gate from prior verified #468 package, `research/hcsn/independent_gate.py` local SHA256 `da04c2135c63d04a32c997421730c2f97565e5b5bf582e0341d3347590bb1a13`, executed against an empty untrusted bundle: **exit code 2**, P0..P6 OPEN, `full_closure=false`, `independent_attestation_verified=false`, `production_activation=false`. `strict_gate.json` SHA256 `7b895f6758982fc19030c9c39d72707b6e179e7d9c695c2fa93f86fc04c53203`.

## Reproduce (Python 3, NumPy, SciPy; from #512 checkout)

```bash
export PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
python -m unittest \
  research.hcsn.test_p2_markov_defective_firsthit \
  research.hcsn.test_p2_defective_first_hit_clock \
  research.hcsn.test_p2_first_hit_renewal_falsification \
  research.hcsn.test_p2_physical_hazard_clock -v
python -m research.hcsn.p2_markov_defective_evidence \
  --samples 45000 --output /tmp/hcsn-iteration33-markov-defective-raw.json
mkdir -p /tmp/hcsn-iteration33-empty-untrusted
python -m research.hcsn.independent_gate \
  --bundle /tmp/hcsn-iteration33-empty-untrusted \
  --strict --output /tmp/hcsn-iteration33-gate.json
# Must exit nonzero (observed 2); never allow empty bundle to pass.
```

SHA256 of added source and unmodified raw evidence:

- `research/hcsn/p2_markov_defective_firsthit.py` = `27818f94bccbce75050472f3de7d11657bc5701e7faf9aba911904bd7ac86ef1`
- `research/hcsn/test_p2_markov_defective_firsthit.py` = `5cb79deae3a090b2d2fe47993838a69dd35099fb4048dfd296015bf000ca3f75`
- `research/hcsn/p2_markov_defective_evidence.py` = `d5d5a1a83fff82a275cdd9e4df1be8ec2cd6c4986180ae890b5564d5b7412662`
- `research/hcsn/gates/2026-11-03-iteration33-markov-defective-raw.json` = `840399acfe262e43450d2f5f0ac2d89a65bc0e87a24156ffc9da7b2443726d99`

There is no real input-conditioned learned moving boundary, no autonomous MQAR/Selective Copy proof, no P1 matched parameter/slope/FLOP/training-win, no full original HX Eq8/11/12/A7 QVI/low-precision coverage, no independently heldout pretrained multimodal encoders, no CPU/GPU joule/p95/p99 production comparison, and no P6 model-scale quality–cost frontier. Preserve previous negative results; **do not merge main**, loosen signatures or activate production. The presence of a GitHub commit cannot close any scientific gate and remote CI must be checked separately.
