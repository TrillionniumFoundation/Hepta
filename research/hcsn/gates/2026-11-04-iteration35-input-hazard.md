# HCSN Iteration 35 — causal input-conditioned marked hazard

**Draft #512 research only. P0–P6 OPEN, DENY_ALL, production_activation=false.**

## Scientific scope
A two-mode causal competing marked exponential hazard, with lambda_ij(x)=R_ij*exp(beta*x), R=[[4,.25],[.7,.07]] per physical second. Each event samples its destination jointly and persists a residual unit-exponential budget across observation refinements and causal input changes; multiple events can occur. Only the final parity of the event count is provided as the downstream training label for the scalar beta. No event timestamps, counts or hidden modes are observed by training.

**This is not original He–Xiong Eq8/11/12/A7, Brownian free-boundary first passage, regenerative QVI, pretrained HCSN, or Selective Copy/MQAR; no P1 FLOP/slope/parameter fairness is established.** Previous Iterations 27/29/31/34 negative results are retained.

Three independent seeds (11,23,37), beta_true=1, train 15 x values in [-.9,.9] with 200 parity outcomes/value. Heldout x values [-1.8,-1.4,1.4,1.8] with 300 outcomes/value.

| seed | beta fitted | OOD NLL fitted | OOD NLL constant-null beta=0 | OOD NLL true beta |
|---|---:|---:|---:|---:|
| 11 | 1.0127 | .676136 | .695346 | .675963 |
| 23 | 1.3116 | .687411 | .694926 | .673841 |
| 37 | 1.2545 | .673942 | .695206 | .668050 |

Within this narrow model-correct synthetic family, a one-parameter task-only fit beats the frozen constant-intensity null on three seeds, but the fitted parameter is imperfect and the oracle OOD loss is better. This is a limited mechanics test, NOT proof of broader HCSN advantage, causal P1 benefits or successful free-boundary learning.

Independent SciPy Kolmogorov ODE vs 4x4 matrix exponential maximal absolute discrepancy: 4.23e-13. Fixed-seed Monte Carlo parity, 1-vs-64 time-grid event invariance, future-input causality and atomic budget rollback tested. Combined local tests (new 7 + prior 46) 53/53 pass. Original #468 independent_gate.py SHA256 da04c2135c63d04a32c997421730c2f97565e5b5bf582e0341d3347590bb1a13 executed with no external trust root: STRICT EXIT 2, P0–P6 all OPEN, full_closure=false, production_activation=false. No remote CI success claimed.

## Reproduce on this exact Draft commit

    export PYTHONPATH=. OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1
    python -m unittest -v research.hcsn.test_p2_joint_input_hazard
    python -m research.hcsn.p2_joint_input_hazard_evidence --train-n 200 --test-n 300 --output /tmp/iter35-replay.json
    base64 -d research/hcsn/gates/2026-11-04-iteration35-input-hazard-raw.json.gz.b64 | gzip -dc > /tmp/iter35-raw.json
    sha256sum /tmp/iter35-raw.json
    # Expected 05a336a6a83406b4ef79f9eb593466cf5e9fce16769d241ec148c903aff54ef5

Run the strict independent gate ONLY from the separate frozen #468 checkout: python -m research.hcsn.independent_gate --bundle /tmp/hcsn-empty-untrusted --strict --output /tmp/hcsn-gate.json; without an externally managed trust root, exit 2 is required.

Executed SHA256: model=b6966104905cfe78f57b9d8d525cd0fa8cbb7e347baa8a19a271a5ae6625df74; test=66835c027845c15ab275c1f6c2e0a308f48a5e03fb3ef867baf94de20cc96baa; evidence=0b8e154bc79b6ab8def153080c8c0b888f48878a81bbae3ff88c0296d8263268; lossless encoded raw=0ca350b69561d1e6c600df3dfb52661aa43f1fea93185b081ea46cbf096fe3b5.

## Branch safety and unclosed obligations

Before writing, compared main 125d11c5454835a7df1dc51915fc49901fbede5b, #468 00a9dc11714f35866be18cd4fece5ce3addefc4a, #481 407201690a617629255d7f5d0968ce4c544c1b93, #486 1aa8eb5f0efc2661472aa5a11221c07553152a03 and #512 old 0cce7ea3ccf5882bda9844334941f0b82fcf62d2. All Draft, PR files for 17 related HCSN branches inspected, new paths additive. #468 CodeQL check 124550087193 remains FAILED; annotations not visible. Library checkpoint version8 independently verified SHA256 814bce86248025013478edd6b2fa68f8052e12b1cfa048593687ccccee2bba6d, 1024 members, verified source 5887/6116 (229 not verified); no Library deletion.

Still OPEN: global HX/QVI/low precision P0; matched slope/parameter/FLOP/budget P1; actual trained continuous moving Brownian boundary, Selective Copy/MQAR long-memory multi-reset OOD P2; text/audio/image/video pretrained heldouts P3–4; real CPU/GPU energy/RSS/p95/p99 P5; medium-model quality-cost P6; independent scientific trust. No main merge, signing relaxation or production activation.
