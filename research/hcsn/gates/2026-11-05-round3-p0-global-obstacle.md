# P0 round 3 — continuous original-HX obstacle certificates

**2026-11-05 · exact source base `1fbc0c275d7f93398ad6643f859551c8f5a85ea0` · continuation of Draft #527**

This round resolves the two exact-input original-HX examples that round 2
left outside its sufficient obstacle domain. It also certifies the entire
FP32 and BF16 original-input preimage boxes for the former Green-overflow
example. The proof covers every continuation state, including the infinite
tail; a finite grid of equity observations does not supply that conclusion.
The full P0 scientific phase and P1–P5 remain OPEN.

## Executed outcome

The same frozen 20-parameter panel is evaluated as exact binary64 inputs
and as whole FP32/BF16 original-input preimage boxes, for 60 attempted rows.
All previous rejections and unresolved outcomes are preserved in the raw
receipt, including six rows where the new condition exceeds its cell budget.
Those six already have valid round-2 sufficient-domain certificates and
retain them. The two sufficient criteria are complementary.

| Input contract | Previous sufficient certificates | Union after this round | Local obstacle refutations | Nonpositive Eq12 candidates | Still unresolved |
|---|---:|---:|---:|---:|---:|
| Exact original binary64 tuples | 14 | 16 | 3 | 1 | 0 |
| Entire FP32 preimage boxes | 13 | 14 | 2 | 1 | 3 |
| Entire BF16 preimage boxes | 10 | 11 | 2 | 1 | 6 |
| Total attempted rows | 37 | 41 | 7 | 3 | 9 |

These are classifications of this fixed panel, not coverage percentages of
the full parameter domain. FP32/BF16 refers to information in the input
encoding; the certificate itself executes CPU interval arithmetic.

| Newly certified row | Finite closed intervals covering `[0,1]` | Uniform lower bound on `q'(x)` for all `x>=1` |
|---|---:|---:|
| Exact negative-cashflow collision point | 4 | `9.419247449514302` |
| Exact former Green-overflow point | 10 | `0.1371763655764677` |
| Green-overflow FP32 preimage box | 10 | `0.13717633691144204` |
| Green-overflow BF16 preimage box | 11 | `0.13418694373356876` |

At the collision point, `tax=.3999077379072307` and
`q(0)` lies in `[-3.72728938256381e-9,-3.727289382563809e-9]`.
Its initial derivative is approximately `-25.44648`, so a condition requiring
cashflow to increase everywhere would fail. Here the first three intervals
prove negative cashflow, and the last interval and infinite tail prove
positive derivative. Its opposite-sign neighbor still refutes the local
obstacle. Both neighbors still encode to the same FP32/BF16 vectors, and
both whole encoding boxes correctly remain `UNRESOLVED_LOCAL_SIGN`.

Independent implementation checks used MP100 evaluation and automatic
differentiation of the debt-price expression without the interval derivative
routine: **231 cell samples and 48 tail samples passed**. The checks include
the original tuples and both all-lower/all-upper corners of the newly
accepted quantization boxes. Twelve separately integrated original Eq11
Green values are positive over margins from `1e-8` to `8`. These finite
numerical observations check the implementation; they are not the proof.

The complete existing mathematics group plus eight new tests ran as
**120 distinct tests, zero failures/errors/skips**. The unchanged strict
empty-evidence gate exits **2**, with scientific phases still OPEN. The
60-row numerical run took about 73.46 seconds on the recorded CPU runtime.

## 1. The mathematical problem is still the original fixed-debt stopping problem

Use the original finite-maturity He–Xiong bond price, the Eq11 equity
cashflow, and the **exact** Eq12 candidate `b>0`. Write

\[
x=\log(V/b),\quad D=\sigma^2/2,\quad\nu=r-\delta-D,
\qquad D s^2+\nu s-r=D(s-\eta)(s+\gamma),
\]

where `eta>1` and `gamma>0`, and

\[
q(x)=\delta b e^x-(1-\pi)C+d_b(be^x,m)-P/m.
\]

The debt-price function is fixed to the Eq8 price computed with barrier `b`.
As in round 2, its explicitly specified extension below the barrier is
`d_b(V,m)=alpha*V/m`. No repricing of debt under arbitrary alternative
default policies is asserted. The original model equations are in
[He and Xiong (2012), Eqs 1–12 and Appendix A](https://www.princeton.edu/~wxiong/papers/rollover.pdf).

The simplified one-shot stopping kernel, fixed-threshold renewal model,
fixed-reset optimal QVI, and state-dependent numerical QVI remain distinct
objects. This certificate proves none of their stronger or different claims.

## 2. A more general sufficient condition

**Proposition.** Under the positive-rate, positive-volatility and finite
maturity assumptions already stated in round 2, let `b` be the exact positive
Eq12 candidate. Suppose

\[
q(0)<0,\qquad
\forall x\ge0:\quad q(x)<0\quad\text{or}\quad q'(x)>0.
\]

Then the smooth-fit nonexplosive equity is strictly positive on `V>b` and
zero on `V<=b`, and is the stopping value for the fixed debt-price problem
with the stated absorbing-recovery extension.

**Single crossing.** The original debt price is bounded and `delta*b>0`,
so `q(x)` tends to positive infinity. At every zero, the stated condition
forces a strictly positive derivative. Starting from negative cashflow,
there is therefore exactly one zero, crossing from negative to positive.
A subsequent positive-to-negative crossing would contradict the condition.
Unlike the previous recovery-monotonicity condition, this argument permits
negative derivatives while cashflow remains negative.

**Smooth-fit integral.** Let `p=P/m`, `c0=C/(m*lambda)`,
`ell=exp(-lambda*m)`, and let `I_F,I_G` denote the Eq12 Laplace integrals.
The original closed boundary formula gives the exact identity

\[
\int_0^\infty e^{-\eta y}q(y)\,dy
=b\left[\frac\delta{\eta-1}+\frac\alpha m I_G\right]
-\left\{\frac{(1-\pi)C+(1-\ell)(p-c_0)}\eta
 +\ell(p-c_0)I_F+c_0 I_G\right\}=0.
\]

Define `J(x)=integral_0^x exp(-eta*y)*q(y) dy`. Before the crossing it is
strictly negative. After the crossing, it equals the negative of the
strictly positive remaining tail and is again strictly negative.

**Positive equity.** From `D E''+nu E'-r E=-q` and `E(0)=E'(0)=0`,

\[
F=E'+\gamma E,
\qquad F(x)=-e^{\eta x}J(x)/D>0,
\qquad E(x)=e^{-\gamma x}\int_0^x e^{\gamma u}F(u)\,du>0.
\]

**Stopping and transversality.** Below the barrier the extended running
reward is `(delta+alpha/m)*V-(1-tax)*C-P/m`, whose maximum over `V<=b`
equals `q(0)<0`. Thus the stopping obstacle and continuation equation hold,
and smooth fit removes the local-time term at the boundary. Because debt
prices are bounded, `q(x)=delta*b*exp(x)+O(1)`; the integral expression for
`F` then gives `E(x)=b*exp(x)+O(1)` at infinity. In particular equity has
at most affine growth in `V`. The identity
`E[exp(-r*t)*V_t]=V_0*exp(-delta*t)` makes its discounted terminal term
vanish in the localized Itô/optional-sampling argument. Running reward has
integrable affine positive part and bounded negative part. This verifies
optimality of the first hit of `b` for this fixed-price stopping problem.

The proposition is sufficient. Failing to certify it is not proof of an
invalid equity model or an incorrect Eq12 candidate.

## 3. How the executable certificate covers a continuum

The new `hx_global_obstacle.py` reuses the existing outward interval
enclosure of the exact Eq12 root. It does not plug a rounded root into the
zero-integral identity. With a low-precision input format, every operation
covers the full legal-original-input preimage box from round 2.

On each closed finite interval `[lo,hi]`, it first tries to prove `q'>0`.
Otherwise it uses the mean-value inclusion

\[
q([lo,hi])\subset q(lo)+[0,hi-lo]\,q'([lo,hi]).
\]

If the resulting upper bound is negative, the whole interval satisfies the
cashflow branch of the proposition. At `lo=0`, the exact enclosed boundary
cashflow avoids cancellation in the literal bond-price expression. If
neither condition is proved, the interval is split. Every final serialized
bound must retain a strict sign even after outward binary64 export.
Successful covers are checked for ordered endpoints, exact joins, and no
gaps. Reaching the cell, depth or tail budget returns an unresolved status;
it cannot create a successful certificate.

### Infinite tail

Set `t=sigma*sqrt(m)`, `a=nu/sigma^2`, and
`z=sqrt(a^2+2*lambda/sigma^2)`. For `X>z*t^2`, all required tail
denominators are positive. Let `H=phi(X/t+a*t)`. The elementary normal-tail
bound `Phi(-u)<=phi(u)/u` for `u>0` follows by replacing `1` by `v/u`
inside the tail integral. Related Mills bounds are documented in
[NIST DLMF §7.8](https://dlmf.nist.gov/7.8).

The two derivative bounds used are

\[
|F'(x)|\le H\left(\frac2t+\frac{2|a|}{X/t-at}\right)=B_F,
\]

\[
|G'(x)|\le H e^{-\lambda m}\left(
\frac2t+\frac{|z-a|}{X/t+zt}+\frac{|z+a|}{X/t-zt}\right)=B_G
\quad(x\ge X).
\]

The Gaussian factors combine exactly:
`exp(-2*a*x)*phi(x/t-a*t)=phi(x/t+a*t)`; the two corresponding `G`
products equal this factor times `exp(-lambda*m)`. Once `X>z*t^2`, the
Gaussian decreases and all displayed denominators increase with `x`.
Consequently

\[
q'(x)\ge\delta b e^X-e^{-\lambda m}|p-c_0|B_F
                 -|\alpha b/m-c_0|B_G\quad\text{for every }x\ge X.
\]

An outward positive lower bound completes the infinite cover. Every sign
assumption is checked jointly over the parameter box. Very small tail
bounds export outward as a positive subnormal when appropriate, not as an
incorrect singleton zero.

## 4. Independent review and limits

The separate `hcsn_lineage` task agent independently reviewed the
single-crossing proof, smooth-fit identity, stopping extension, mean-value
inclusion and Mills algebra. It also checked 25 MP90 tail samples using
direct debt-price expressions and numerical differentiation. Its internal
review is recorded separately. This is not an externally signed scientific
attestation or a second independently validated interval arithmetic library.

The existing `evaluate_local_mixed_precision` entry point is unchanged and
still requires the older `SUFFICIENT_FIXED_DEBT_OBSTACLE` classification.
The new certificate therefore does **not** authorize additional native
FP32/BF16 returned values through that entry point. Full-state low-precision
evaluation, gradients, tensorization, and device execution remain separate
work. No production gate or admission policy is widened.

The remaining nine unresolved panel rows concern information lost in input
quantization or a root interval that still crosses zero. More generally,
the constructor's broad parameter domain still includes actual local
counterexamples and nonpositive candidates. This work does not admit that
entire domain, prove equilibrium uniqueness under repriced deviations,
certify general regenerative optimal control, or establish neural benefit.

## 5. Reproduction and provenance

From the complete checkout and the recorded Python environment:

```sh
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
python -m unittest research.hcsn.test_hx_global_obstacle -v
python -m research.hcsn.p0_global_obstacle_evidence --output /tmp/hcsn-round3-fresh.json
python -m research.hcsn.independent_gate --bundle research/hcsn --strict
```

The evidence command requires a new output path. The accompanying execution
receipt lists the exact 23 test modules and all 120 distinct test identities.
The raw numerical receipt preserves all 60 rows, incomplete covers,
independent sample values, source hashes and original parameter tuples.
The test logs and JSON were read back successfully and their recorded
source hashes checked after completion.

Files introduced in this round:

- `research/hcsn/hx_global_obstacle.py`: sufficient-condition certificate.
- `research/hcsn/p0_global_obstacle_evidence.py`: frozen-panel replay and independent MP checks.
- `research/hcsn/test_hx_global_obstacle.py`: eight mathematical/adverse regression tests.
- `research/hcsn/gates/2026-11-05-round3-p0-*`: raw outcomes, test logs, execution and internal review.

There is no merge, production activation, or full scientific-phase closure
in this report.
