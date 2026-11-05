# P0 round 2 — original HX domain and low-precision error enclosures

**2026-11-05 UTC · exact base `5d91fac039437928cee1e3f68d9e9e5d22653633` · existing Draft #527**

This round fixes a reproducible overflow in the original HX Green evaluator,
derives a **sufficient global obstacle domain for a fixed HX debt-price
function**, and adds a local mixed-precision evaluation path with an explicit
error enclosure. It preserves the old FP64 boundary and FP32 information-loss
counterexamples. It does not close the full P0 phase or modify any independent
science, signing, production, or merge gate.

## 1. Results that can be asserted

| Item | Actual result | Scope |
| --- | --- | --- |
| Legal-domain Green overflow | Fixed at two reproducible states; MP90 A7 agrees | Original HX, same supplied boundary |
| Sufficient obstacle theorem | Proof below; analytic derivation independently reviewed by another task agent | Fixed debt-price stopping problem; no equilibrium uniqueness claim |
| Eq12 numerical enclosure | 60 attempts: 20 parameter cases, each as an exact point and an FP32/BF16 preimage box | Whole boxes are enclosed by interval inclusion, not corner sampling |
| Independent boundary comparison | All 57 available positive MP120 point references contained | The remaining three rows enclose a nonpositive candidate |
| Local original-HX value enclosure | All 56 independent MP100 Eq11 integrals contained | Four positive log margins, seven parameter cases, two output formats |
| Actual mixed-precision evaluation | 40 accepted, 16 refused for unresolved global domain | FP32 state and accumulation; optional BF16 output storage |
| Worst accepted relative error bound | FP32 `4.268924566194928e-5`; BF16 `0.00336138526975043` | Bounds include approximation and actual arithmetic error; these maxima describe this panel |
| Original native FP32 A7 | Large near-boundary error retained | Direct log margin alone does not repair cancellation |
| Native BF16 A7 | CPU `log_ndtr` unavailable in the executed Torch 2.10 backend | No silent promotion is labeled native BF16 |
| Mathematics regression group | **112 distinct tests, zero failures/errors/skips** | Previous 98 plus 14 new tests on the complete checkout |
| Empty-evidence strict gate | Exit **2**, phases remain OPEN | Original gate code unchanged |

All raw parameter tuples, input boxes, values, error bounds, refusals, source
hashes, and runtime details are in `2026-11-05-round2-p0-hx-numerical.json`.
Execution and dependency hashes are in `2026-11-05-round2-p0-execution.json`.

## 2. The mathematical objects remain separate

This round concerns the **original finite-maturity He–Xiong debt/equity
system**, using Eq8 bond prices, Eq11 equity cashflow and ODE, and the Eq12
smooth-fit candidate. The stationary debt structure and effective bond
discount rate are as specified in the primary paper:
[He and Xiong (2012), *Rollover Risk and Credit Risk*](https://www.princeton.edu/~wxiong/papers/rollover.pdf),
Eqs 1–12 and Appendix A.

The simplified stopping Call/Put kernel, the prescribed-threshold renewal
policy, and the optimal fixed-reset/cost QVI are different mathematical
problems. Their prior tests remain in the 112-test group, but their identities
are not used to establish the full-HX results below. There is no neural
mechanism or benchmark conclusion in this report.

The mathematical assumptions here are

\[
r,\delta,\sigma,m,C,P>0,\quad
\lambda=r+\xi k\ge r,\quad 0\le\alpha\le1,\quad0\le\pi<1.
\]

The implemented input prior is the existing finite exploratory constructor
domain, interpreted as exact original binary64 values:

| Parameter | Implemented prior |
| --- | --- |
| `r` | `[.005, .30]` |
| `delta` | `[.001, .20]` |
| `sigma` | `[.03, .75]` |
| `alpha` | `[0, 1]` |
| `tax` | `[0, 1)` |
| `xi`, `k` | `[0, 10]`, `[0, .25]` |
| `maturity` | `[.05, 10]` |
| `coupon_total`, `face_total` | `(0, 500]`, `(0, 1000]` |

Passing these bounds does **not** imply that a positive smooth-fit candidate
exists or that a positive candidate satisfies the equity obstacle.
For example, `tax=.99, C=500, P=.0001`, with the other paper-baseline inputs,
has the enclosing Eq12 result
`[-1935.9220949705655, -1935.9220949705652]`. Its exact point, whole FP32
preimage, and whole BF16 preimage are all classified
`NO_POSITIVE_EQ12_CANDIDATE`. That is a statement about this candidate, not a
claim that every conceivable financial policy at those parameters is invalid.

## 3. A sufficient original-HX obstacle domain

### Proposition and exact scope

Let `b>0` be the **exact** Eq12 candidate under the assumptions above. Write
`p=P/m`, `c=C/m`, and assume

\[
\boxed{\alpha b\le\min\{P,C/\lambda\}.}
\]

For `V>b`, fix the market debt-price function to the original Eq8 with
barrier `b`. For `V<=b`, use the absorbing-recovery extension
`d_b(V,m)=alpha*V/m`. Then the smooth-fit, nonexplosive equity solution
is strictly positive on `V>b`, is zero on `V<=b`, and satisfies the
infinite-horizon equity stopping variational inequality for this **fixed
debt-price function**. The boundary hitting strategy is optimal for that
stopping problem.

This is a sufficient condition. Failure to establish it does not refute a
candidate. The proposition does not establish equilibrium uniqueness when
debt prices are recomputed under arbitrary deviating default policies or
changed debt structures. It also does not establish a regenerative QVI.

### Proof

Set `D=sigma^2/2`, `nu=r-delta-D`, and let `eta>1`, `-gamma<0` be the roots
of `D*s^2+nu*s-r=0`. The inequality `eta>1` follows from `delta>0`, since
the polynomial at `s=1` is `-delta`. This also makes the affine cashflow tail
integrable against `exp(-eta*x)`.

**Debt monotonicity.** Couple log-state paths started at different
`x=log(V/b)` by the same Brownian path. The boundary hitting time is
nondecreasing in the initial `x`. If default occurs at time `s<m`, the
discounted bond income including accrued coupons is

\[
h(s)=\frac c\lambda+
\left(\frac{\alpha b}{m}-\frac c\lambda\right)e^{-\lambda s}.
\]

At maturity without prior default it is

\[
h(m,\mathrm{survive})=\frac c\lambda+
\left(p-\frac c\lambda\right)e^{-\lambda m}.
\]

The first part is nondecreasing in `s` when `alpha*b<=C/lambda`.
The maturity jump is nonnegative when `alpha*b<=P`. Thus the expected
bond price `d_b(b*exp(x),m)` is nondecreasing in `x`.

**Cashflow and the smooth-fit integral.** Define

\[
q(x)=\delta b e^x-(1-\pi)C+d_b(be^x,m)-p.
\]

It is continuous and strictly increasing, because `delta>0`. It grows
like `delta*b*exp(x)` plus a bounded term. Eq12 is exactly the
smooth-fit identity

\[
\int_0^\infty e^{-\eta y}q(y)\,dy=0.
\]

Consequently `q(0)<0`; `q` crosses zero once; and

\[
J(x)=\int_0^x e^{-\eta y}q(y)\,dy<0\quad(x>0).
\]

Before the crossing, the integral is negative directly. After the crossing,
it is the negative of the strictly positive remaining tail.

**Equity positivity.** The original ODE is
`D*E''+nu*E'-r*E=-q`, with `E(0)=E'(0)=0`.
Let `F=E'+gamma*E`. The characteristic-root identities give

\[
F'-\eta F=-q/D,\qquad
F(x)=-e^{\eta x}J(x)/D>0.
\]

Therefore

\[
E(x)=e^{-\gamma x}\int_0^x e^{\gamma u}F(u)\,du>0
\quad(x>0).
\]

**Stopping side and verification.** Under the explicitly stated recovery
extension, the running reward below `b` is

\[
q_-(V)=(\delta+\alpha/m)V-(1-\pi)C-p.
\]

It is increasing in `V` and at `b` equals `q(0)<0`, so it is
negative everywhere below the boundary. Thus the continuation ODE and
the stopping obstacle inequality both hold, with smooth fit removing the
local-time term. The no-explosive-mode solution has at most affine growth.
Because `E[e^{-rt}V_t]=V_0 e^{-delta*t}` and `r,delta>0`, its discounted
terminal term vanishes. The positive part of the running reward is bounded
by an affine function of `V`, and its negative part is bounded. The usual
localized Itô/optional-sampling argument therefore gives the stopping
verification, with equality for the first hit of `b`.

The proposition concerns the exact Eq12 candidate, **not** a rounded
candidate substituted into an identity as though its residual were zero.
The next section explains how the implementation encloses that exact root.

## 4. What the numerical enclosure actually guarantees

`hx_interval_domain.py` creates a fresh mpmath interval context at 100
decimal digits by default. It uses outward-rounded arithmetic, `exp`,
`sqrt`, and `pi`. It does not call interval `erf`/`erfc`, which failed in the
installed library during inspection.

The normal CDF is enclosed by two explicit formulas:

- For `0<=z<=12`, integrate the alternating series for `exp(-z^2/2)`;
  once terms decrease, consecutive partial sums enclose the remainder.
- For `z>12`, repeated integration by parts encloses the Gaussian tail by
  consecutive partial sums of
  `phi(z)/z * (1-1/z^2+3/z^4-...)`. The remainder has the next sign and is
  bounded by the next term. The method stops before terms grow; it does not
  treat an asymptotic series as convergent.

The formulas and the positive-real remainder property are supported by the
primary NIST references [DLMF §7.6](https://dlmf.nist.gov/7.6) and
[DLMF §7.12](https://dlmf.nist.gov/7.12). For CDF input intervals, monotonicity
reduces the enclosure to its endpoints. Export back to binary64 is checked
against exact dyadic `Fraction` endpoints, including gradual underflow;
for example `Phi(-40)` exports as `[0, smallest_positive_binary64]`, not an
incorrect singleton zero.

For the Eq12 Laplace factors, change variables to

\[
I(k,b,t)=tJ(kt,bt),\qquad
J(s,h)=\int_0^\infty e^{-su}\Phi(h-u)\,du.
\]

`J` decreases in `s` and increases in `h`, giving a box enclosure without
sampling corners. At an exact zero rate it uses
`J(0,h)=h*Phi(h)+phi(h)`. For a nonzero rate smaller than the exact dyadic
`2^-90`, monotonicity brackets it between the evaluations at `-2^-90`
and `+2^-90`. No tiny nonzero rate is silently replaced by its zero limit.

Two exact algebraic identities reduce cancellation:

\[
z-\widehat z=-\frac{2\xi k}{\sigma^2(z+\widehat z)},\qquad
\frac\delta{\eta-1}=\frac{\sigma^2}{2}(\gamma+1).
\]

The second identity is used inside Eq12; it does not expand the implemented
input domain to `delta=0`. Positive characteristic roots are rationalized
where their direct subtraction would be ill-conditioned.

The domain classification uses the enclosed root, enclosed local cashflow,
and enclosed slacks `P-alpha*b`, `C/lambda-alpha*b`. Positive lower slack
bounds and a positive lower root bound establish the sufficient condition
for every tuple in the input box. A positive lower local-cashflow bound
refutes the local equity obstacle. All other cases return explicit
unresolved classifications or arithmetic refusal.

**Arithmetic trust boundary.** This is an executable inclusion certificate
conditional on mpmath's basic interval primitives, whose exact source hashes
are recorded. The [official context documentation](https://mpmath.org/doc/current/contexts.html)
describes inclusion arithmetic and also calls interval support experimental.
The work does not claim an independently verified IEEE-1788 implementation,
a proof-assistant-checked certificate, or an external science attestation.
Independent MP checks exercise the implementation; agreement with MP is not
itself the interval proof.

## 5. Quantized inputs and the exact accepted contract

The FP32/BF16 domain checks enclose the **whole closed preimage cell** under
direct round-to-nearest-even encoding, intersected with the explicitly known
prior that the original parameters passed the constructor domain. Tie
endpoints are included on both sides conservatively. This is an interval
statement, not a sweep over a few rounded inputs.

The encoded center need not itself be a legal input. For example, the legal
original `r=.30` becomes BF16 `.30078125`; the known-prior preimage ends at
`.30`. The original value is checked to be inside the box. The code does not
pretend that a clipped center was the value actually encoded. Direct BF16
rounding is defined explicitly; the observed Torch encodings in this panel
are checked against it.

The retained opposite-local-sign tax pair encodes to the same complete
FP32 input vector and also the same BF16 input vector. Both preimage boxes
return `UNRESOLVED_LOCAL_SIGN`. No calculation downstream of only those
encoded values can recover both original signs. The positive-sign original
point remains a local rejection; the negative-sign point remains outside
the sufficient domain, not automatically admitted.

For state storage, `V` and `b` rounded separately erase the paper-baseline
`x=1e-8` in both formats: the actual reconstructed `log(V/b)` is zero.
The cell analysis returns `UNRESOLVED_QUANTIZED_STATE`; it does not call
that stopping. A directly tracked nonzero log margin retains its positive
side in these cases.

## 6. Full-HX local value and rounding error bound

The new `local_equity_enclosure` supports exact original log margins
`0<=x<=1e-3`. It encloses the original Eq11 fourth-order expansion,

\[
P_4(x)=\tfrac12 E_2x^2+\tfrac16 E_3x^3+\tfrac1{24}E_4x^4,
\]

where the coefficient names denote the respective derivatives at zero:

\[
E_2=-q(0)/D,\quad
E_3=(-q'(0)-\nu E_2)/D,\quad
E_4=(rE_2-\nu E_3-q''(0))/D.
\]

These coefficients are computed from enclosed original Eq8 bond
derivatives. They are not coefficients of the simplified stopping Call.
For a component `exp(c*x)*Phi(z(x))`, `z=-x/t+b*t`, the first three CDF
derivatives are `-phi(z)/t`, `-z*phi(z)/t^2`, and
`-(z^2-1)*phi(z)/t^3`. Product differentiation and interval inclusion give
absolute derivative bounds `Q_j>=sup_[0,x]|q^(j)|`, `j=0..3`.

To bound the remainder, use the exact initial-value Green kernel

\[
K(u)=\frac{e^{\eta u}-e^{-\gamma u}}{D(\eta+\gamma)}.
\]

For `0<=u<=h`, `K'(u)<=exp(eta*h)/D`, hence

\[
B_0=Q_0h^2e^{\eta h}/(2D),\qquad
B_1=Q_0h e^{\eta h}/D
\]

bound `|E|` and `|E'|`. Recursively,

\[
B_{j+2}=\frac{Q_j+|\nu|B_{j+1}+rB_j}{D},\quad j=0,1,2,3.
\]

Therefore the fourth-order Taylor remainder is at most `B5*h^5/120`.
The interval operations include rounding in these bounds. An independent
MP100 implementation integrates `-K(x-y)*q(y)` directly and does not reuse
the Taylor coefficients or this remainder computation.

`evaluate_local_mixed_precision` actually executes a Torch FP32 polynomial,
using FP32 coefficient storage and a directly supplied FP32 log margin; it
optionally converts the final value to BF16. It compares the actual returned
binary value with the entire original-input equity enclosure. The upper
error bound is calculated with exact rational differences and rounded
outward. Thus state rounding, coefficient rounding, evaluation rounding,
BF16 output rounding, and Taylor truncation are all included.

The default relative error tolerances are `1e-4` for FP32 output and `.01`
for BF16 output. A nonzero result is accepted only if the sufficient global
domain is established, the true-value enclosure is strictly positive, and
the conservative relative error bound meets the tolerance. The exact zero
state has an explicit zero-value case. Otherwise the public `value` is
`None`; a signed `candidate_value` remains available solely for diagnostics.
Strict-tolerance failures and underflow-to-zero failures are tested.

This contract **retains original binary64 parameters**. It cannot recover
parameters already lost to BF16. The interval controller and coefficient
preparation are CPU research computations, not a fused neural operator.
There is no native-all-BF16, gradient, latency, or energy claim.

## 7. Reproduced defects, retained counterexamples, and observed coverage

### Green overflow repaired

For `r=.30, delta=.001, sigma=.03, xi=0` with the other paper-baseline
inputs, `gamma=664.4477838833548`. The old Green integrand separately
formed `exp(gamma*y)`, which overflows even though the final integrand is
bounded. The new algebraically identical factor is

\[
e^{-\gamma(x-y)}[-\operatorname{expm1}(-(\eta+\gamma)y)].
\]

Both factors are in `[0,1]` for `0<=y<=x`.

| Log margin | Exact old-commit execution | Repaired FP64 | MP90 A7, same supplied boundary |
| --- | --- | ---: | ---: |
| `2` | `OverflowError: math range error` | `322.4491543467383` | `322.4491543467383` |
| `8` | `OverflowError: math range error` | `150381.71617733547` | `150381.7161773355` |

The audit loads the actual `hx_original.py` git object at the base SHA to
reproduce the old failure; it does not reconstruct a minimal shadow. This
parameter point remains outside the newly proved sufficient domain. Fixing
its numerical overflow does not establish its global obstacle admissibility.

### Prior FP64 Eq12 counterexamples retained

The old raw `closed_boundary` routine still provides the historical
counterexamples and its existing wrapper still refuses them. The new
interval entrance encloses their exact roots instead of using those raw
roots as though they were accurate:

| Case | Eq12 enclosure |
| --- | --- |
| Paper | `[67.44151539060364, 67.44151539060366]` |
| Prior A | `[7.375289962124613, 7.375289962124614]` |
| Prior B | `[9.332614563433324e-6, 9.332614563433326e-6]` |

The exact A/B points and their full FP32 preimages satisfy the sufficient
domain; their BF16 preimages remain unresolved. The paper BF16 preimage's
boundary interval is `[64.01358135322356, 70.96217736617092]`, and the
sufficient slacks remain nonnegative throughout that whole box.

### The 20-case panel

| Classification | Exact original point | FP32 preimage | BF16 preimage |
| --- | ---: | ---: | ---: |
| Sufficient fixed-debt obstacle domain | 14 | 13 | 10 |
| Refuted by positive local cashflow | 3 | 2 | 2 |
| No positive Eq12 candidate | 1 | 1 | 1 |
| Local sign unresolved | 0 | 2 | 3 |
| Positive candidate unresolved | 0 | 1 | 3 |
| Outside sufficient domain, not refuted | 2 | 1 | 1 |

The panel includes exact/tiny zero-liquidity limits, short/long maturity,
low/high volatility, zero/full recovery, near-one tax, tiny positive
cashflows, the old sign and precision counterexamples, and the new overflow
witness. Every attempted row is retained. These counts describe the panel;
they do not estimate an acceptance probability over the parameter space.

### Native arithmetic failures are not hidden by input quantization

For paper parameters and `x=1e-8`, actual CPU native FP32 Eq12/A7 returns
`3.24249267578125e-5`, while the independent original-input value is
`4.637232516930513e-14`. At `x=.001`, it returns
`.0007762908935546875`, compared with `.0004628860780123308`.
The audit separately recomputes the encoded-parameter model at MP precision;
the large remaining error belongs to arithmetic, not merely to changed
inputs. It uses `exp(log_amp+log_ndtr(z))` where supported, matching the
existing FP64 tail treatment, rather than deliberately using an overflowing
naive product.

Across 16 native literal attempts, two are finite, four have a nonpositive
or nonfinite boundary, and ten explicitly refuse or lack a backend special
function. The zero-liquidity A7 removable denominator is refused, not
silently divided by zero. All eight BF16 attempts report the actual
`log_ndtr_cpu` unsupported operation in Torch 2.10. These are findings about
the executed CPU backend, not a universal impossibility of BF16 algorithms.

## 8. Reproduction, provenance, and remaining blockers

Use the existing repository Python environment and one numerical thread:

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
python research/hcsn/2026-11-05-round2-p0-hx-audit.py --output /tmp/hcsn-round2-hx.json
python -m unittest research.hcsn.test_hx_round2_domain -v
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

The audit is create-only. The complete 22-module/112-test argument list and
every distinct test ID are recorded in the execution JSON, alongside hashes
of executed local source and the mpmath primitive files. The numeric run used
Python 3.12.14, NumPy 2.3.5, SciPy 1.17.0, mpmath 1.3.0, and Torch 2.10.0+cpu.
This is a complete checkout replay of that mathematics group, not all-repo
CI or an independently signed acceptance run.

The analytic sufficient condition and the Taylor remainder derivation were
independently reviewed by the P1 task agent. That internal review is not
represented as an external scientific trust-root signature.

The following remain open and are stated concretely:

1. **Parameters outside the sufficient obstacle condition.** The exact
   negative-sign collision point and the overflow witness remain unproved
   by this criterion. They are not mislabeled invalid. The broad original
   constructor domain also contains actual local-obstacle counterexamples
   and nonpositive Eq12 candidates; it cannot be globally admitted unchanged.
2. **A stable full-state-range native FP32/BF16 HX operator.** The new
   error-enclosed value path covers `0<=x<=1e-3`. Far-field A7, gradients,
   vectorized GPU behavior, compiler fusion, and repeated state updates need
   separate work. A CPU interval controller is not an efficiency result.
3. **Input information already lost.** Only rounded parameter/state values
   cannot identify the retained opposite-sign cases. The implementation
   explicitly requires original parameters or returns a whole-cell verdict.
4. **The stronger arithmetic and model claims.** A second validated interval
   library or formal checker has not independently certified the arithmetic
   trust base; arbitrary repriced-policy equilibrium uniqueness and general
   state-dependent regenerative QVI remain outside this proposition.
5. **Independent phase admission and neural benefit.** No evidence-signing
   policy is changed, no signature is fabricated, and no P0–P5 benefit follows
   from a financial numerical certificate alone.

The precise advancement is a repaired original-HX reference, an analytically
specified global fixed-debt stopping subset with interval domain checks, and
an actually executed local mixed-precision path whose accepted values carry
an explicit error bound. The original scientific phase remains OPEN.
