# HCSN iteration 5 supplementary adversarial checks — 2026-10-31

Research-only; **P0–P6 all OPEN; production disabled.** Supplements, not overwrites, `STATUS_ITERATION5.md`.

## P0 original He–Xiong bond Eq.(8) independent PDE stress

- Test file: `test_bond_fd_stress.py` (frozen `numpy.random.default_rng(62844)`).
- 50 HXParams tuples in declared finite domain; 5 log states per case (`x=0.12,0.3,0.7,1.3,2.0`); 250 independent finite-difference vs Eq.(8) comparisons.
- PDE grid: log xmax=7, 501 points, 1300 implicit time steps per case, paper formula evaluated separately.
- **All 250** below preregistered 0.001 relative-error threshold; observed max relative error `0.0004935247382669256`; observed mean relative error `0.00006246113113470682`; max absolute error `0.009049144239014595` bond units.
- Validated finite random panel only; no global-domain, tight interval arithmetic or low-precision error theorem.

## P2 event-time exact-piecewise gradient adversarial check

- Test file: `test_autonomous_stress.py` (frozen PRNG seed 902114).
- 100 randomly generated irregular four-segment trajectories; 20 rejected because an event fell within 0.04 time units of an input segment endpoint (nonsmooth assignment region); **80** robust trajectories retained with 2–6 endogenous reset events each.
- Ten signed autograd versus central finite-difference sensitivity checks per accepted trajectory (initial margin, reset margin, each depletion rate and each interval length); all **800** under `3e-6` absolute tolerance.
- This does not prove differentiability at event collisions or through changes in event count; those discontinuities are explicit and remain open.

## Acceptance and git status

- Local CPU suite: `OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s hcsn_round5_20261031 -p 'test_*.py' -q` => **78 tests OK**.
- Strict P0–P6 gate: **exit 2** expected. Main branch is not merged or production activated.
- Remote: `TrillionniumFoundation/Hepta`, research branch `research/hcsn-qvi-nonlocal-and-p1-controls-20261031`, draft PR #468.
- Environment: CPU-only PyTorch; pretrained multimodal model weights and GPU/power telemetry are absent; no P3–P6 closure claim.
