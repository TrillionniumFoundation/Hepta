# HCSN P0–P6 Iteration 6 — 2026-10-31 independent stochastic cross-check

**Research only. P0–P6 scientific gates remain OPEN; deployment activation remains false.** This checkpoint adds an independently implemented stochastic reference for the *original* He–Xiong bond formula, not a claim about the neural Call/Put gain.

## Source interpretation

Zhiguo He and Wei Xiong, *Rollover Risk and Credit Risk*, Journal of Finance 67(2):391–430 (2012), original Eq. (8) on printed page 399; original bond PDE and boundary conditions Eqs. (5)–(7). Full author manuscript: https://www.princeton.edu/~wxiong/papers/rollover.pdf. This finite cash-flow Monte Carlo comparison checks the **original bond value**, not the novel proposed neural Put activation or full equity (A7), moving-boundary QVI, or general HCSN model.

## New reference and reproducible evidence

- `research/hcsn/first_passage_mc.py`: independently samples first passage of drifted log-GBM using NumPy's inverse Gaussian/Wald RNG. For upward drift, accounts for the non-hitting mass `exp(-2 mu x / sigma²)`; for zero drift samples the Levy law. In each path, pays discounted coupons until the stopping time plus liquidation recovery at default **or** principal at maturity. No calls to Eq. (8) F/G during payoff generation, no Euler path discretization.
- `research/hcsn/test_first_passage_mc.py`: three tests, including four fixed-seed cash-flow panels, negative/positive/zero-drift eventual-hitting mixture, rejected invalid inputs.
- `research/hcsn/p0_mc_evidence.py`: emits per-statistic estimate, analytic value, MC standard error, signed z score, instrument parameters, source SHA256, environment and all-gate OPEN status. Fails on overwrite and uses a distinct nonzero exit on 6-SE panel failure.
- Four 120,000-path panels = **480,000** simulated stopping times, 12 F/G/bond comparisons. All 12 inside exploratory six-standard-error sanity envelope. Max observed |z| **0.9750644793951784**; max absolute bond-value difference **0.020364325376299064** (bond value units). Seeds 10201, 10202, 10203, 10204. Cases include positive, negative, and exactly zero log drift and zero liquidity-cost product.
- **Important design caveat:** finite sample, seed and the acceptance envelope are not independently preregistered and share the original GBM assumptions; the six-SE envelope is a debugging criterion, *not* a proven confidence bound or independent scientific replication.

## Execution (repo-root)

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python -m research.hcsn.p0_mc_evidence --output /tmp/hcsn_p0_mc_new.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

Local equivalent bundle location used for actual fresh test execution: `/mnt/data/hcsn_round5_20261031`; replace `research.hcsn` with `hcsn_round5_20261031` in module commands when running extracted local bundle.

**Locally executed in Python 3.13.5, NumPy 2.3.5, SciPy 1.17.0, PyTorch 2.10.0+cpu: 85/85 remote-branch tracked unittest cases passed** (four additional local-only equity-FD tests were excluded from this precise count). The independent Ed25519 external-trust-root gate still exits **2** with all P0–P6 OPEN because no release-authority trust root was supplied. The existing research gate also exits **2**. This is expected fail-closed behavior, not scientific acceptance.

Exact Git blob SHAs (verified GitHub file contents against locally run byte-identical files):

| File | Blob SHA |
| --- | --- |
| `first_passage_mc.py` | `9de8d6d98d9ee304cfbbfadcaf0484f025b6226d` |
| `test_first_passage_mc.py` | `4f483eed6351b57236ff71b872c4178032083982` |
| `p0_mc_evidence.py` | `a27745b97c8f2e4c6bff9c9afdea86fd6326bf0e` |

Local panel JSON SHA256: `4c19c65ea818ba02cd3ba1387aeab8051f753bf5810074fa02441c3f373e9848` (the file is an execution artifact, not embedded in the PR).


## Added deterministic F/G density-quadrature cross-check

- `research/hcsn/first_passage_quad.py` integrates the original drifted-Brownian first-passage **density**, not the normal-CDF closed form. The variable change `y=x/(sigma*sqrt(t))` and *geometric subintervals* resolve the narrow small-margin boundary layer that a naive one-interval `quad(lo, +inf)` can silently miss. In a pilot random panel, naive integration disagreed by as much as **9.557e-7** for near-boundary inputs; geometric subdivision removed this numerical artifact in the checked domain.
- `research/hcsn/test_first_passage_quad.py` adds four tests: 500 seeded cases/1000 F/G comparisons, another postimplementation 2000 seeded cases/4000 comparisons with shorter relative maturities, explicit `x=1e-9` boundary-layer regression, zero-liquidity bond-value check and fail-closed invalid-domain checks.
- Across **2,500** explored parameter cases / **5,000** F/G comparisons the observed maximum absolute discrepancy from the original analytically evaluated CDFs was **1.3877787807814457e-15**. This is strong *bounded numerical agreement*, not an analytical or floating-point global bound; the numerical integration is limited to `x>=1e-12` and `tau>=1e-12` for strictly positive inputs.
- The second 2,000-case panel was selected after method development; **neither** panel is independently preregistered. No neural utility or production acceleration has been demonstrated by this quadrature.
- Exact Git blob SHAs after remote verification: `first_passage_quad.py` = `58b9ab5030f3120c04b7aa71c2e18ab8ce0f1f59`; `test_first_passage_quad.py` = `8f48e799826a26dc1089d9def620ceff62aeddd9`.


## Reproduction path hardening: original A7 high-precision limit

The remote `hx_a7_mp_regularized.py` and its `test_hx_a7_mp_regularized.py` previously used package-relative-only imports, which are invalid when Python `unittest discover -s research/hcsn` imports test files as top-level modules. Both now use relative imports with top-level discovery fallbacks. **No high-precision formula or tolerance was changed** in this repair.

The two updated remote files were reproduced byte for byte locally (Git blob SHAs `a91f55f22935a75f20020afac09c33d9b5624e2e` and `b2caea993251d01bc84febfa65ab90aad5fddd61`), and their three numerical/negative tests passed under `python -m unittest discover -s hcsn_a7_remote_test -p 'test_*.py' -v`. A clean local rehearsal that combined the earlier 85-test bundle with these three byte-matched remote A7 tests passed **88/88**, excluding separate uncommitted local-only equity-FD experiments. This is not a CI run and not an all-files remote SHA audit.

External trust-root verification remains OPEN, so full closure and production activation remain false.

## Blocker disposition, no overstated closure

| Gate | Current disqualifying missing evidence |
| --- | --- |
| P0 | Global parameter-domain & original A7 coupled-equity and QVI verification; low precision and hardware parity |
| P1 | Independently held-out improvement versus strong ordinary gates matched in signed slopes, parameters and compute; previous equal-parameter C1 lookup is behaviorally indistinguishable |
| P2 | Multi-seed autonomous-spike long-horizon Selective Copy/MQAR and meaningful joint recall; strict event-count surface handling |
| P3 | Actual pretrained text, audio, image, and video encoder models and matched strong baselines |
| P4 | Real multimodal temporal/entity alignment, missing-modality retrieval and negative-transfer outcomes |
| P5 | Real target GPU kernels, joules, sustained full-encoder CPU/GPU throughput, p99 and RSS |
| P6 | Medium pretrained model distillation/continued pretraining and preregistered quality-cost frontier |

The next high-information P0 experiment is a *held-out* independent all-domain A7/Green/FD comparison with numerical error certificates and extreme low precision. P1–P6 are not advanced by merely passing this stochastic bond reference. PR #468 remains **Draft**, base `main`, no merge.
