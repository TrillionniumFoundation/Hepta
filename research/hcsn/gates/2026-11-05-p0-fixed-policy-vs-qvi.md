# P0: separate fixed-policy renewal from optimal fixed-reset QVI

Research continuation of Draft #527 at exact base
`406fb358a15850af2d8063e98d900ff275fe121b`.
Executed from a complete Git checkout with local source changes, not a
reconstructed dependency subset. The accompanying JSON binds the actual
source files by SHA-256. This is a scoped numerical repair and comparison;
the original HCSN scientific gates remain OPEN.

## Two concrete defects reproduced before repair

Both inputs are inside the existing `RegenerativeParams` constructor domain.
The original exact Git object was also executed separately after repair to
retain the failures; no original source or previous evidence was edited.

| Input | Original result | Corrected result / independent reference |
|---|---|---|
| `r=.001, delta=.2, sigma=.01`, log-distance `.2`, horizon `1` | `OverflowError` at `exp(796.2)` | CDF `0.47210346477886217`; direct first-hit-density quadrature `0.47210346477886134` |
| `R=.01, cost=.0099999999999999`, otherwise defaults | Brent bracket has no sign change because the true root is below the hard-coded `1e-13` lower bound | Boundary `6.163350831450351e-17`; independent MP80 bisection agrees at displayed binary64 precision |

The CDF now combines the reflected Gaussian exponent before evaluating it.
For nonpositive log drift, the reflected term is
`0.5 * exp(-z1*z1/2) * erfcx(-z2/sqrt(2))`; its two factors are bounded.
Positive log drift uses the nonpositive original exponential and retains the
non-hitting probability mass. Inputs are not changed to fit the reference.

The boundary solver now uses dimensionless variables. Near the maximum
cost it solves for `b/(R-cost)`; near zero cost it solves for `log(R/b)` and
evaluates the quadratic small-cost expression as a combined series. The
characteristic root is rationalized in the cancellation-prone drift regime.
If binary64 cannot distinguish the trigger from the reset point, the solver
raises an explicit numerical refusal. This is not a claim to support every
positive real cost in finite precision.

## Four different mathematical problems

| Problem | Equation / boundary meaning | Scope in this checkout |
|---|---|---|
| Original He–Xiong | Finite-maturity debt PDE (5)–(8), coupled equity ODE (11), candidate default boundary (12) / A7 | Existing original-HX references and admissibility counterexamples retained; this change does not establish their global obstacle condition |
| Simplified one-shot stopping | `max((L-r)C + delta*v-r*K, -C)=0`; terminal stopping payoff zero | Existing `math_kernel.py`, unchanged |
| Fixed threshold policy with repeated reset | A supplied `0<b<R`; wait until hitting `b`, pay `c`, reset to `R`, repeat | New `fixed_policy_value`; no threshold optimization or smooth-pasting condition is imposed |
| Optimal intervention with fixed reset target/cost | `max((L-r)U + delta*v-r*K, U(R)-c-U(v))=0`; optimize intervention timing | Existing `regenerative_value` / `reset_boundary`, with repaired numerical evaluation and independent fixed-policy comparisons |

Here `dV/V=(r-delta)dt+sigma*dW`, all model parameters are the existing
bounded exploratory parameters, and there is **no abandonment action** in
the repeated-reset model. Therefore a poor fixed policy may have negative
value. Clipping such a value to zero would solve a different problem.
The fixed-target QVI does not optimize the reset endpoint, reset map,
context-dependent parameters, or a neural training objective.

### Fixed-policy renewal equation

Let `gamma>0` be the decaying characteristic exponent and
`H_b(v)=(b/v)^gamma` the discounted hitting transform for `v>b`.
The expected reward of a single cycle is

`(v-K) - H_b(v)*(b-K)`.

Solving the scalar renewal equation at `R` gives

`U_b(v) = v-K + H_b(v)*(R-b-c)/(1-H_b(R))` for `v>b`.

For `v<=b`, the fixed policy resets immediately and
`U_b(v)=U_b(R)-c`. The implementation uses `expm1` for the renewal
denominator and `log1p` for nearby states. A threshold just below `R`
correctly retains the very large negative repeated-cost value.

### Why the optimized value is a different object

For the fixed `R,c` model, the smooth-fit equation is

`gamma*(R-b-c) = b*(1-(b/R)^gamma)`.

Its residual decreases strictly on `(0,R-c)`, with opposite endpoint
signs. At its root, the renewal bonus equals `b/gamma`.
In the continuation region,

`U'(v)=1-(b/v)^(gamma+1)>0`,

so the impulse branch `U(R)-c-U(v)` is nonpositive. The characteristic
equation and value matching give, throughout the reset region,

`(L-r)U+f = delta*(v-b) - sigma^2*(gamma+1)*b/2 <= 0`.

These identities explain the two QVI branches for this particular model.
The tests also solve a different numerical problem: directly maximize
the renewal value, whose discounted hitting factors are obtained by
integrating the first-passage density. That optimization does not call the
analytic threshold equation. Numerical sampling is not an interval proof
of all real inputs or a proof for the original financial HX model.

## Executed finite evidence

Runtime: Python 3.12.14, NumPy 2.3.5, SciPy 1.17.0, mpmath 1.3.0;
all numerical thread counts fixed to one. CPU observations only.

- Unmodified exact-base mathematical subset: **81 tests passed, zero skips**.
- Corrected mathematical subset plus original reference integration module:
  **98 distinct tests passed, zero skips** (86 existing and 12 new).
- **100 CDF cases** across negative, zero and positive drift, low volatility,
  broad diffusion, distances and horizons: maximum absolute error against
  independently recomputed MP80 formula **4.440892098500626e-16**.
- **6 boundary cases**, including very small cost and cost near `R`:
  maximum relative error against MP80 bisection
  **1.8871013254405301e-16**.
- **15 fixed-policy values** compared with independent first-hit-density
  integration: maximum absolute error **1.7319479184152442e-14**.
- **3 threshold optimizations** using that density/renewal reference:
  maximum relative boundary difference **7.777312733893338e-9**.
  In each configuration, the optimal value dominates the 245 evaluated
  state/policy pairs; these are 49 supplied policies at five states.
- Independent finite-difference QVI, unchanged, on the same finite log
  domain: refining `h=.04,.02,.01` reduces value error at the reset state
  from `5.3600e-4` to `7.6354e-5` to `1.0199e-5`.
  The finest-grid discrete complementarity residual is `3.4751e-11`.
- Strict empty-evidence gate still exits **2** with every upstream phase OPEN.

All raw numerical cases, negative baseline outcomes, source fingerprints,
and executed test identities accompany this report. The density Laplace
integral uses finite log-time limits `[-28,28]` only for the stated moderate
reference cases. QVI finite differences retain an asymptotic upper boundary.
Neither truncation is asserted to be a global outward-rounded error bound.

## Reproduction

From this exact research checkout, with the runtime versions above:

```sh
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
python -m unittest research.hcsn.test_regenerative_policy_audit research.hcsn.test_regenerative_qvi research.hcsn.test_qvi_fd_reference research.hcsn.test_contextual_qvi research.hcsn.test_hcsn_reference -v
python -m research.hcsn.p0_regenerative_policy_audit --output /tmp/hcsn-fixed-policy-fresh.json
```

For the exact 98-case set, load the module names recorded in
`2026-11-05-p0-fixed-policy-execution.json` with `unittest`.
The output path must not already exist. Test execution and source identity
do not supply an independent external scientific signoff.

## Primary references and remaining scope

- [He and Xiong, Rollover Risk and Credit Risk, final 2012 paper](https://www.princeton.edu/~wxiong/papers/rollover.pdf): the original coupled debt/equity problem, not the repeated-reset model introduced here.
- [Azimzadeh, Bayraktar and Labahn, convergence of implicit HJBQVI schemes](https://arxiv.org/html/1705.02922v5): nonlocal consistency, monotonicity, stability and comparison requirements.
- [Azimzadeh and Forsyth, weakly chained matrices and impulse control](https://arxiv.org/html/1510.03928v5): implicit-policy solvability requires more than a small computed residual.

Original HX global admissibility, FP32/BF16 implementation, general
state-dependent optimal regeneration, learned event-time gradients, mechanism
advantage, real multimodal experiments, device energy and scale remain open.
No production admission or full P0 closure follows from this repair.
