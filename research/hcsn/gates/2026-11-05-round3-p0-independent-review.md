# P0 round 3: separate task-agent mathematical review

This records messages returned by the read-only `hcsn_lineage` task agent
during this execution. It is an internal independent derivation/implementation
review, not an external scientific signature or a certified second arithmetic
implementation. The reviewing agent did not edit the implementation.

## Analytical review

The reviewer independently derived that, for `q` continuously differentiable,
the conditions `q(0)<0`, `q(x)->infinity`, and `q(x)<0 or q'(x)>0` everywhere
imply exactly one negative-to-positive crossing. At a later crossing back to
negative, the derivative requirement would be violated. With the exact Eq12
discounted integral equal to zero, every partial integral is negative; the
factored equity ODE therefore gives positive equity.

The reviewer expanded the smooth-fit identity as

`b*[delta/(eta-1)+alpha*I_G/m]`
`- {[(1-tax)*C+(1-ell)*(p-c0)]/eta+ell*(p-c0)*I_F+c0*I_G}=0`.

It explicitly required the below-boundary extension `d_b(V,m)=alpha*V/m`
and the affine growth/transversality argument before calling the result a
stopping verification. Both are present in the round-3 report.

The reviewer checked the new source `hx_global_obstacle.py` and confirmed:

- `exp(-2*a*x)*phi(x/t-a*t)=phi(x/t+a*t)` in the `F'` bound.
- Both `G'` Gaussian products equal the same factor times `ell` because
  `z^2-a^2=2*lambda/sigma^2`.
- `X>z*t^2` makes the Mills denominators and Gaussian argument positive;
  the Gaussian decreases and the denominators increase over the entire tail.
- The absolute-value debt derivative bound and increasing affine term
  give a conservative uniform lower bound on `q'`.
- Parameter-box interval operations and finite-cell mean-value inclusion
  are conservative; the final no-gap cover check is appropriate.

No formula or accepting-path error was identified. The review also noticed
that the old mixed-precision value entry point does not accept the new
status. This round preserves that boundary and documents it explicitly.

## Separate MP90 numerical cross-check

The reviewer executed `/workspace/scratch/a20378baf59f/.venv/bin/python`
from the isolated P0 checkout, with a cloned MP context at 90 decimal digits.
It differentiated direct `F/G` Gaussian-CDF expressions using `mp.diff`,
without calling `_forcing_derivatives`. Each case checked
`x=X+[0,.125,1,4,16]` against the exported uniform tail bounds. The boundary
was independently recomputed by the existing high-precision Eq12 reference.
All **25 high-precision assertions passed**, with shell exit code zero.

| Case | X | Largest observed `abs(F')/F_bound` | Largest observed `abs(G')/G_bound` | Smallest observed `q'-lower_bound` |
|---|---:|---:|---:|---:|
| Paper | 2 | 0.9997793449824651 | 0.9682431849971291 | 3.145884366902138e-15 |
| Negative-cashflow collision point | 2 | 0.9997898147326898 | 0.7957034955865203 | 7.665565236797886e-8 |
| Former overflow point | 2 | 0 after binary64 reporting | 0 after binary64 reporting | 5.1236136557819874e-17 |
| Paper parameters, maturity 10 | 3 | 0.9930597413387111 | 0.8567644223932279 | 0.00013795624669807847 |
| Paper parameters, sigma .75 | 2 | 0.8268058231170808 | 0.785982905901007 | 5.163550520415719 |

The zero ratios for the overflow row reflect extremely small ratios below
binary64 report range; the comparisons themselves were performed in MP90.
These finite points only cross-check the implementation. The global claim
depends on the analytic argument and outward interval cover, not this table.

The committed evidence runner additionally records its own 231 MP100 cell
checks, 48 MP100 tail checks, and 12 independent Green integrals, including
all values rather than only these reviewer-provided aggregates.
