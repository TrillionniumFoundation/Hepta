# HCSN P0 Iteration 45 — independent original Eq8/11/12/A7 and separate QVI audit

**2026-11-06 · Research only · parent Draft #527 exact HEAD \`069ff1ee1f65baff65a0b12340e68cfdae0b2588\` · P0–P6 OPEN**

This increment adds a standalone numerical implementation. It imports no \`research.hcsn\` source module and does not modify the frozen HX implementation, the P0 interval certificate, any training experiment, production code, or gate policy.

## Reproduction

Pinned environment: Python 3.13.5, NumPy 2.3.5, SciPy 1.17.0, mpmath 1.3.0.

\`\`\`bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \\
  python -m unittest research.hcsn.test_p0_independent_eq8_a7_qvi_audit -v

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \\
  python -m research.hcsn.p0_independent_eq8_a7_qvi_audit \\
  --output /tmp/hcsn-iteration45-independent.json

python -m research.hcsn.independent_gate --bundle research/hcsn --strict
# Expected strict result without an externally provisioned trust root: exit 2.
\`\`\`

The exact-head GitHub workflow repeats the tests, emits a fresh raw JSON artifact, verifies the committed SHA-256 manifest, and asserts that the strict gate remains nonzero.

## Original He–Xiong equations

The standalone reference reconstructs the original finite-maturity Eq8 first-passage factors \(F,G\), obtains the Eq12 boundary from direct improper Laplace quadrature, and obtains the Eq11 smooth-fit boundary by solving a separately integrated forcing equation with adaptive quadrature and a bracketed root. It evaluates the literal Appendix-A7 expression and compares it against a separately integrated Eq11 Green representation.

- Deterministic random panel: 40 admissible parameter tuples, seed \`20261106\`; 1 additional candidate rejected by the reference-domain guards.
- Maximum relative Eq12 vs direct Eq11-root boundary discrepancy: **4.215124133559993e-16**.
- Maximum relative literal A7 vs Green equity discrepancy: **2.6900703886667543e-12**.
- Paper baseline: both independently computed boundaries \`67.44151539060367\`.
- Baseline A7/Green values were compared at log margins \`1e-4, 1e-3, 0.01, 0.1, 1, 3, 8\`; the largest relative discrepancy was \`2.0344489981560798e-13\`.

These are finite numerical cross-checks. They do not replace the outward-rounded continuum certificates, prove all legal parameter tuples, or prove a globally admissible original-HX stopping policy.

## Preserved FP32 information-loss negative

A separate MP60 direct first-passage integration re-evaluated the frozen tax pair:

- Tax values \`0.39990773048821086366...\` and \`0.39990773790723072733...\` have identical FP32 bits \`b5c0cc3e\`.
- Their Eq12 boundaries have identical FP32 bits \`de9b3942\`.
- Their original Eq11 boundary cashflows have opposite signs, approximately \`+3.72728934635e-9\` and \`-3.72728934635e-9\`.
- Both liquidation recovery/face ratios remain below one.

The positive-cashflow member is a local obstacle rejection; the negative-cashflow member passes only this necessary local sign test and is **not** admitted. This preserves the existing negative result: an FP32-only input path cannot distinguish the pair and must use higher-precision input, a certified interval fallback, or refusal.

## Separate fixed-reset QVI control

A separately coded sparse policy-iteration solver evaluates the *new fixed-reset GBM impulse QVI*, not the original He–Xiong financial QVI. On one frozen parameter set, mesh widths \`0.04, 0.02, 0.01\` gave:

| Mesh | Boundary absolute error | Max value absolute error | Complementarity residual |
|---:|---:|---:|---:|
| 0.04 | 0.05504790745 | 0.00800870920 | 1.71e-12 |
| 0.02 | 0.01125893295 | 0.00198661518 | 7.92e-12 |
| 0.01 | 0.00408763880 | 0.00048106504 | 3.48e-11 |

Boundary and value errors decrease under refinement. This is only a numerical control for the separate constant-reset QVI; it does not establish the general endogenous, state-dependent, or repriced He–Xiong QVI.

## Strict decision and limits

All P0–P6 remain **OPEN**. The standalone audit has no external scientific trust-root signature, no global interval proof for the full legal HX domain, no complete low-precision input-box certificate, and no general original-HX QVI proof. It supplies no matched P1 training benefit, learned P2 dynamic-boundary/MQAR/OOD result, real multimodal P3/P4 heldout, target CPU/GPU energy/RSS/p95/p99, or P6 medium-model quality-cost frontier.

\`external_scientific_attestation=false\`, \`full_original_hx_domain_proved=false\`, \`original_hx_low_precision_certified=false\`, \`general_endogenous_qvi_proved=false\`, and \`production_activation=false\` are explicit in the raw JSON. Keep Draft/HOLD/DENY_ALL. No main merge, signature relaxation, or production activation.
