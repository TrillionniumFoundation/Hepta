# HCSN P2 iteration 22: hidden first-hit probability between sampled tokens

**RESEARCH ONLY — all P0–P6 OPEN; DENY_ALL / NO_GO; production_activation=false.**
No main merge, signed-scientific gate change, external attestation or deployment.

## Frozen ancestry, inspected before incremental commit

- main: 125d11c5454835a7df1dc51915fc49901fbede5b.
- Draft #468 HEAD 00a9dc11714f35866be18cd4fece5ce3addefc4a, base main.
- Draft #481 HEAD 407201690a617629255d7f5d0968ce4c544c1b93, base original HCSN research branch at 819e33f691e9a3a255a74a6088789512e65ba951.
- Draft #486 HEAD 1aa8eb5f0efc2661472aa5a11221c07553152a03, base #481 at 407201690a617629255d7f5d0968ce4c544c1b93.
- This Draft #512 BEFORE this increment: HEAD 5111a26294efd685c5970a880e608fb2c5e86867; base #505 at 2ce3267ca148a6568497cc20b27c09c26058b739.
- Other Draft P2 #487/#492/#498/#500/#503/#505/#511; P0 #509/#526/#527; P1 #513 inspected and left untouched. In particular #500 already studies two-stage moving affine boundary/bridge first-hit integrals. No overlap with that solver: this increment focuses on discrete-observation hidden crossings and causal sampled path risk.
- No confirmed PR-triggered GitHub workflow runs at the sampled SHAs; not an assertion of complete CI status.

## New independent mathematical obstruction to P2 event semantics

For Brownian signed margin with constant diffusion sigma and deterministic affine barrier on an observation interval dt, if both observed endpoints are positive, the conditional probability of an *unobserved* barrier crossing is:

    P(hidden hit | m0>0,m1>0)=exp(-2*m0*m1/(sigma^2*dt)).

At x0=0.4, zero drift, sigma=0.4 per sqrt(second), T=1 second:

- Endpoint-only binary detector P(X_T<=0): 0.15865525393145707.
- Actual continuous first-hit probability: 0.3173105078629142.
- **Probability mass missed by the endpoint detector: 0.15865525393145713 (50% of true hits).**

An elapsed-time refractory clock does not recover crossing events that were never observed. A Brownian-bridge probability is a *risk*, not a recovered sampled spike, a differentiable realized hitting time or learned autonomous reset.

## Implemented

- p2_hidden_bridge_hits.py: bounded FP64 conditional bridge-hit law, independent first-hit CDF and causal streaming log-survival over interval endpoints; validates timestamps, diffusion, sample shapes and prior states. Only applies to constant volatility and affine deterministic barriers within each interval.
- test_p2_hidden_bridge_hits.py: 10 actual local tests: endpoint-only negative witness; four independent Gaussian endpoint integrations against reflection principle; exact bridge Bernoulli Monte Carlo (180k draws); chunk/causal prefix equality; time-unit scaling; affine barrier translation; finite-difference sensitivity; extreme tails; malformed/replayed state fail-closed; no false training claim.
- p2_hidden_bridge_evidence.py: deterministic, overwrite-refusing raw JSON generator; uses seed 492001 and records source SHA256.
- gates/2026-10-31-iteration22-hidden-bridge-hits.json: four fixed cases and 180000-draw Monte Carlo raw results.

## Actually executed local tests (NOT complete remote checkout)

Python 3.13.5 / NumPy 2.3.5 / SciPy 1.17.0, CPU.

    PYTHONPATH=. python -m unittest research.hcsn.test_p2_hidden_bridge_hits -v
    PYTHONPATH=. python -m research.hcsn.p2_hidden_bridge_evidence --output /tmp/hcsn-p2-hidden-bridge-iteration22.json
    python -m research.hcsn.independent_gate --bundle research/hcsn --strict

Focused tests: **10/10 PASS, zero skipped**. Four independent Gaussian/first-hit crosschecks maximum absolute discrepancy 5.551115123125783e-17, limited to listed cases and standard floating-point error; not a globally certified bound. Exact bridge-conditional MC: 106852/180000 crossings, empirical 0.5936222222222223 versus reflection prediction 0.5948609674885499, deviation 1.0705538 binomial standard errors.

Scientific gate source Git blob 4611f0569f62bff00d932b7b7e95743dbbccbc29 was fetched from this branch and matched the local gate. Its STRICT execution exited **2**; all P0–P6 OPEN and production_activation=false: independent evaluator/observer external trust root and scientifically sufficient evidence are absent.

Remote source/test/generator Git blob hashes were read back after upload and matched the exact executed local file bytes. Full remote CI and full repository checkout remain unverified. Code uses SciPy and NumPy; no pretrained encoder, GPU power measurements, training result or actual sampled reset timestamps are present.

## OPEN blocker ledger (not a certification)

P0 original HX Eq8/11/12/A7 global/low-precision/QVI, P1 matched-slope/parameters/FLOP/train-budget independent advantage (retain ordinary-gate negative results), P2 learned input-driven boundaries, multiple actual autonomous events, Selective Copy/MQAR and OOD, P3/P4 real four-modal pretrained encoders and crossmodal heldout, P5 real GPU/energy/RSS/p95/p99, P6 medium model quality-cost frontier. All OPEN and never relaxed for this incremental scientific counterexample.
