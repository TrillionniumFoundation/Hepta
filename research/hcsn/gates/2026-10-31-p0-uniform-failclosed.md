# HCSN P0 — fail-closed uniform HX research evaluator, 2026-10-31

**Research only | P0–P6 OPEN | production_activation=false | no main merge**

## Frozen basis and isolation

- GitHub main HEAD at initial inspection: `125d11c5454835a7df1dc51915fc49901fbede5b`.
- Parent research [Draft #468](https://github.com/TrillionniumFoundation/Hepta/pull/468): exact starting HEAD `00a9dc11714f35866be18cd4fece5ce3addefc4a`, based on `main`.
- Adjacent P2 research [#481](https://github.com/TrillionniumFoundation/Hepta/pull/481), [#486](https://github.com/TrillionniumFoundation/Hepta/pull/486), [#492](https://github.com/TrillionniumFoundation/Hepta/pull/492), [#498](https://github.com/TrillionniumFoundation/Hepta/pull/498), [#500](https://github.com/TrillionniumFoundation/Hepta/pull/500), [#503](https://github.com/TrillionniumFoundation/Hepta/pull/503), [#505](https://github.com/TrillionniumFoundation/Hepta/pull/505) were read, not modified.
- No production, CI, evidence-signature or release-authority changes. This child branch is deliberately stacked on Draft #468 to preserve research separation.

## Failure mode corrected

`hx_uniform.equity_logmargin` previously returned a zero-equity value after clipping negative computed continuation equity whenever `-1e-7*max(1,b) <= val < 0`. Existing P0 finance counterexample (r=.10, delta=.075, sigma=.20, alpha=.40, tax=.27, xi=4, k=.20, m=3, C=5, P=100) satisfies original Eq12 smooth fit but has positive net boundary cash flow and hence `E_xx(0+)<0`. For sufficiently small positive log margin, its equity is negative yet could be silently clipped. In addition, a caller-supplied candidate boundary was only checked for positivity, not agreement with Eq12.

The new fail-closed reference:
1. Validates `HXParams` type and recomputes Eq12 root even with an externally supplied boundary.
2. Rejects an external boundary inconsistent with Eq12 to within a specified 1e-12 relative/absolute numerical tolerance.
3. Checks the *necessary-only* original HX Eq11 smooth-fit boundary net cash flow `q_B=delta*b-(1-tax)*C+alpha*b/m-P/m`; refuses cases with `q_B >= -1e-9*scale` as either locally invalid or numerically unresolved.
4. Raises on *every* negative computed continuation equity instead of silently projecting to zero.
5. Exposes `global_obstacle_certified=false` and `production_activation=false` in the research evaluator result.

**Limitations:** the relative sign buffer is empirical, not an outward-rounded error enclosure. Recomputing Eq12 is an equality cross-check, not a certified global obstacle solution. Even a negative `q_B` is only absence of this one local obstruction. No theoretical all-parameter, FP32/BF16, QVI, gradient or neural benefit claim follows.

## Actual scoped execution

Using Python 3.11+ with available NumPy/SciPy, six focused `unittest` tests passed in an **isolated locally reconstructed minimal subset**:

```text
test_baseline_no_local_obstruction_does_not_imply_admission ... ok
test_invalid_smooth_fit_candidate_is_refused_at_all_distances ... ok
test_near_threshold_unresolved_sign_fails_closed_in_both_directions ... ok
test_negative_continuation_never_projected_to_zero ... ok
test_parameter_type_and_numeric_guards ... ok
test_supplied_boundary_cannot_bypass_eq12 ... ok
Ran 6 tests — OK
```

The local replay included only the original Eq12 analytic implementation and Taylor local expansion, reconstructed from the parent source; **it was not an exact remote branch checkout** and did not exercise the Green/A7 paths, the complete old `test_hx_uniform.py` suite, or GitHub CI. Both changed Python files were read back from GitHub after commit: their returned Git blob SHA-1s equal the exact locally executed bytes:

- `research/hcsn/hx_uniform.py`: `e3efcbd6ec4d45268f03a8e4befe4f213e451ddb` (SHA256 `9badfc4d3526b04c44684544d3234b7503407f3e9d18ef142f4239eafc84bcf3`).
- `research/hcsn/test_hx_uniform_failclosed.py`: `044983e02da0e4bfaf884314d7a67259e4284866` (SHA256 `8d5fd5438c4d9be93cc6b88c49903c58cd8efa1aed8c157c71b613a149c0f10a`).

## Independent reviewer next commands (repo root)

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_hx_uniform_failclosed -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_hx_uniform -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest research.hcsn.test_hx_local_obstacle_sign -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s research/hcsn -p 'test_*.py' -q
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
# External scientific evidence absent: expected exit 2, NOT a test failure or PASS.
```

## Remaining open gates

P0 complete original HX coupled obstacle and state-dependent regenerative QVI, independent all-domain and directed-interval/low-precision proof; P1 equal-slope/parameter/FLOP/training-budget causal gain; P2 learned multiple autonomous resets, Selective Copy/MQAR irregular time across seeds; P3/P4 real pretrained four-modal encoders and heldout alignment, missing-modality/noise, negative-transfer comparisons; P5 CPU/GPU fused full-model 64/256/1024/4096 Cell throughput, peak RSS, p95/p99, Joules, failure/recovery; P6 medium-scale backbone quality-cost frontier. The user's P4 native-kernel and P5 scaling labels correspond to the existing ledger's P5 and P6 respectively.

**Keep Draft and never deploy/merge based on this scoped test.**
