"""Independent high-precision first-passage quadrature for HX local sign.

Numerically integrates F and G from the original first-passage law and
constructs smooth-fit Eq12 without using hx_integrals, closed_boundary,
Green equity, FD equity, or the binary64 local sign function. It is a
pointwise consistency check ONLY, not rigorous interval arithmetic.
"""
from __future__ import annotations

import math
import mpmath as mp


def _d(x):
    if not isinstance(x,(float,int)) or isinstance(x,bool) or not math.isfinite(x):
        raise ValueError('Finite scalar parameter required')
    return mp.mpf(str(x))


def mp_first_passage_sign(p, *, decimal_digits=50):
    if not isinstance(decimal_digits,int) or isinstance(decimal_digits,bool) or not 30<=decimal_digits<=100:
        raise ValueError('High-precision work digits must be 30..100')
    # Deliberately extract the concrete parameter names instead of borrowing
    # the implementation or cached Laplace expression under test.
    with mp.workdps(decimal_digits):
        r,delta,sigma,alpha,tax,xi,k,m,C,P=[_d(getattr(p,name)) for name in (
            'r','delta','sigma','alpha','tax','xi','k','maturity','coupon_total','face_total')]
        if (r<=0 or delta<=0 or sigma<=0 or not 0<=alpha<=1 or not 0<=tax<1
                or xi<0 or k<0 or m<=0 or C<=0 or P<=0):
            raise ValueError('Invalid high-precision physical parameters')
        lam=r+xi*k
        a=(r-delta-sigma*sigma/2)/(sigma*sigma)
        z=mp.sqrt(a*a+2*r/(sigma*sigma))
        zh=mp.sqrt(a*a+2*lam/(sigma*sigma))
        eta=z-a
        if eta<=1:
            raise ArithmeticError('No finite affine equity far-field resolvent')
        t=sigma*mp.sqrt(m)
        Phi=lambda v: mp.erfc(-v/mp.sqrt(2))/2
        def F(x):
            return (Phi((-x-a*sigma*sigma*m)/t)
                    +mp.exp(-2*a*x)*Phi((-x+a*sigma*sigma*m)/t))
        def G(x):
            return (mp.exp((-a+zh)*x)*Phi((-x-zh*sigma*sigma*m)/t)
                   +mp.exp((-a-zh)*x)*Phi((-x+zh*sigma*sigma*m)/t))
        grid=[0,mp.mpf('.1'),mp.mpf('.5'),1,2,5,10,mp.inf]
        I_f=mp.quad(lambda x:mp.exp(-eta*x)*F(x),grid)
        I_g=mp.quad(lambda x:mp.exp(-eta*x)*G(x),grid)
        c0=(C/m)/lam
        u=P/m-c0
        num=((1-tax)*C+(1-mp.exp(-lam*m))*u)/eta +mp.exp(-lam*m)*u*I_f+c0*I_g
        den=delta/(eta-1)+alpha/m*I_g
        if den<=0:
            raise ArithmeticError('No positive admissible denominator')
        b=num/den
        net=delta*b-(1-tax)*C+alpha*b/m-P/m
        curv=-2*net/(sigma*sigma)
        if not all(mp.isfinite(z) for z in (b,net,curv,I_f,I_g)) or b<=0:
            raise ArithmeticError('Nonfinite/invalid high-precision reference')
        return {
            'working_decimal_digits':decimal_digits,
            'boundary':mp.nstr(b,decimal_digits),
            'boundary_cashflow':mp.nstr(net,decimal_digits),
            'boundary_log_curvature':mp.nstr(curv,decimal_digits),
            'I_f':mp.nstr(I_f,decimal_digits),
            'I_g':mp.nstr(I_g,decimal_digits),
            'recovery_over_face':mp.nstr(alpha*b/P,decimal_digits),
            'negative_curvature_observed':bool(curv<0),
            'scoped_to_single_parameter_point':True,
            'globally_certified':False,
            'outward_rounded_intervals':False,
            'production_activation':False,
        }
