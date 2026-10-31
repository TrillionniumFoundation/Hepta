# HCSN P0 iteration 13: FP32-identical original HX inputs with opposite local obstacle signs

2026-10-31 | RESEARCH ONLY | P0-P6 OPEN | production_activation=false

## Frozen source and overlap checks

Original main SHA: 125d11c5454835a7df1dc51915fc49901fbede5b. Original HCSN Draft PR #468: research/hcsn-qvi-nonlocal-and-p1-controls-20261031, pre-increment HEAD 9182edb594cfa744af707789d176ed9864d61f26, base main. Adjacent #481 HEAD 407201690a617629255d7f5d0968ce4c544c1b93; #486 HEAD 1aa8eb5f0efc2661472aa5a11221c07553152a03. Both are separate stacked research branches. Also inspected #483, #487, #492, #498; none were modified. Only additive files to original #468, no production or gate configuration edits.

## New scientific negative finding

Original He–Xiong Eq8 at the Eq12 candidate boundary has d(VB,m)=alpha*VB/m. Under C2 smooth fit, the original Eq11 local log-curvature is E_xx(0+)=-2*q_B/sigma^2, with q_B=delta*VB-(1-tax)*C+alpha*VB/m-P/m. A positive q_B causes negative equity immediately above the candidate boundary and REJECTS its global obstacle admissibility. Negative q_B establishes NO global validity.

Holding (r,delta,sigma,alpha,xi,k,m,C,P)=(.10,.075,.20,.40,4,.20,3,5,20), both original Eq12 VB and q_B are affine in t=1-tax. Independent first-passage CDF quadrature in mpmath at 50 digits yields algebraic zero tax:

0.39990773419772079549603859397359420739245583074699

| Case | tax (MP50) | Boundary q_B (MP50) | Local curvature sign |
|---|---|---|---|
| A | 0.39990773048821086366402572931572947159497055383133 | +3.727289346353610144e-9 | Negative: local rejection |
| B | 0.39990773790723072732805145863145894318994110766265 | -3.727289346353610144e-9 | Positive: not independently admitted |

The two distinct tax inputs encode to identical float32 bytes b5c0cc3e; both distinct Eq12 boundaries encode to identical float32 bytes de9b3942. The entire input vector has the same FP32 representation. Recovery/face is 0.92804 (<1) for both. A separately implemented existing 50-digit first-passage reference reproduced both opposing signs; 70-digit rerun stabilized the zero to better than 1e-46.

**Information-theoretic counterexample:** an implementation that sees only these rounded FP32 inputs cannot recover both original signed local equity conditions. Higher-precision original inputs, a verified interval error budget or explicit refusal are necessary near the sign threshold. Higher CDF precision inside FP32 cannot recover input digits already lost. This is scoped negative evidence, not a proof for all parameter values or a neural benchmark.

## Files, commands, actual results

New files: hx_fp32_local_sign_collision.py; test_hx_fp32_local_sign_collision.py; p0_fp32_local_sign_evidence.py; gates/2026-10-31-iteration13-fp32-local-sign-evidence.json; this report. All under research/hcsn.

Locally reproduced on Python 3.13.5 CPU, NumPy/SciPy/mpmath, from an isolated research subset with the exact prior hx_local_obstacle_mp_reference.py file (NOT a complete remote-branch checkout or CI):

    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_hx_fp32_local_sign_collision.py' -v
    # Ran 9 tests in 2.186s; 9/9 PASS, zero skips
    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m research.hcsn.p0_fp32_local_sign_evidence --output /tmp/hcsn-p0-iteration13.json
    # create-only, full raw pair and local-source SHA256

SHA256 of executed and remote-byte-matched source/test/evidence:
- hx_fp32_local_sign_collision.py: 524a37e28de8dfd33f39716ccbfa4e01f9f4e83f310205bf54db63d7b34b9fb0
- test_hx_fp32_local_sign_collision.py: 3376e67e49c2e69b7d1634e83788b77ed5ee114863dd656e08290aff01ee450a
- p0_fp32_local_sign_evidence.py: f9c14586b45d34c4babf36f38f3aa80f1052e54942ba7f662066fd62570890de
- prior hx_local_obstacle_mp_reference.py: 40b45f00f6c184e08fdf4afeb113a6486f3f46366294a393b2336828edbfdc8e
- complete raw JSON: 883b10adc3b068e8d2ae7c3be461845ffb9dbad667542ea3f6a52540a52384ea

## Strict admission

P0 OPEN: global original HX coupled obstacle and dynamic QVI, low-precision interval/fallback proof missing.
P1 OPEN: fair matched signed slope/parameters/FLOPs/training compute and positive heldout causal gain missing; previous negative results retained.
P2 OPEN: trainable endogenous long-range autonomous multi-FIRE, Selective Copy/MQAR and multi-seed OOD not validated.
P3/P4 OPEN: real four-modal pretrained encoders and independent cross-modal heldouts missing.
P5 OPEN: real target CPU/GPU fused operator energy, RSS, end-to-end p95/p99 missing.
P6 OPEN: medium pretrained encoder and quality-cost frontier missing.

External-trust-root signed scientific evidence is absent. The existing independent_gate.py and its fail-closed strict mode are unchanged; --strict must continue exiting code 2 without complete externally reviewed evidence. This round did NOT run the full original branch gate or whole-repo CI and does not claim either passed. Never merge main, weaken signature checks or enable production.
