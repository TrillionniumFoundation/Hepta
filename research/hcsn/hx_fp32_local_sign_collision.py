"""P0 negative test: original He--Xiong Eq8/11/12 local sign is not FP32-identifiable.

An explicitly constructed pair of legally bounded financial inputs differs in
binary64 tax rate but COLLAPSES to one identical binary32 input vector and one
identical binary32 Eq12 boundary. Their original Eq11 local curvature signs are
opposite. An unassisted FP32 gate cannot classify both correctly, regardless of
its implementation. This is not a global HX proof or neural operator benchmark.

Construction independently integrates first-passage F/G at 50-digit precision;
no call to the production/root helper under test. Inputs are canonical decimal
strings converted exactly to arbitrary precision before evaluation.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, replace
import math
import mpmath as mp
import numpy as np


@dataclass(frozen=True)
class FinancialPoint:
    r: str = '.10'
    delta: str = '.075'
    sigma: str = '.20'
    alpha: str = '.40'
    tax: str = '.27'
    xi: str = '4.'
    k: str = '.20'
    maturity: str = '3.'
    coupon_total: str = '5.'
    face_total: str = '20.'


def _mp_first_passage_integrals(p: FinancialPoint, dps: int):
    """Independent direct density-integral Eq8 Laplace factors, no Eq12 helper."""
    if not isinstance(dps,int) or isinstance(dps,bool) or not 45<=dps<=90:
        raise ValueError('Requires 45..90 working decimal digits')
    q={k:mp.mpf(v) for k,v in asdict(p).items()}
    r,delta,sigma,xi,k,m=(q[x] for x in ('r','delta','sigma','xi','k','maturity'))
    if not (r>delta>0 and sigma>0 and xi>=0 and k>=0 and m>0):
        raise ValueError('Outside this finite reference region')
    lam=r+xi*k
    a=(r-delta-sigma**2/2)/sigma**2
    eta=mp.sqrt(a*a+2*r/sigma**2)-a
    zh=mp.sqrt(a*a+2*lam/sigma**2)
    if eta<=1: raise ArithmeticError('Nonintegrable equity affine tail')
    tt=sigma*mp.sqrt(m)
    phi=lambda z:mp.erfc(-z/mp.sqrt(2))/2
    def F(x):
        return phi((-x-a*sigma*sigma*m)/tt)+mp.exp(-2*a*x)*phi((-x+a*sigma*sigma*m)/tt)
    def G(x):
        return (mp.exp((-a+zh)*x)*phi((-x-zh*sigma*sigma*m)/tt)
               +mp.exp((-a-zh)*x)*phi((-x+zh*sigma*sigma*m)/tt))
    split=[mp.mpf('0'),mp.mpf('.1'),mp.mpf('.5'),1,2,5,10,mp.inf]
    IF=mp.quad(lambda x:mp.exp(-eta*x)*F(x),split)
    IG=mp.quad(lambda x:mp.exp(-eta*x)*G(x),split)
    return q,lam,eta,IF,IG


def collision_evidence(*,digits: int=50) -> dict:
    """Build opposite-sign finance points that encode to one FP32 input.

    Smooth-fit Eq12 is affine in t=(1-tax) at fixed other parameters; this
    gives an *algebraic* zero of the local obstacle sign, not a fitted root.
    """
    p=FinancialPoint()
    with mp.workdps(digits):
        q,lam,eta,IF,IG=_mp_first_passage_integrals(p,digits)
        r,delta,sigma,alpha,m,C,P=(q[n] for n in
                ('r','delta','sigma','alpha','maturity','coupon_total','face_total'))
        c0=(C/m)/lam; u=P/m-c0
        A=(1-mp.exp(-lam*m))*u/eta+mp.exp(-lam*m)*u*IF+c0*IG
        D=delta/(eta-1)+alpha/m*IG
        slope=C*((delta+alpha/m)/(eta*D)-1)
        intercept=(delta+alpha/m)*A/D-P/m
        if D<=0 or slope==0:raise ArithmeticError('Degenerate local sign root')
        tax_critical=1+intercept/slope
        if not mp.mpf('.001')<tax_critical<mp.mpf('.999'):
            raise ArithmeticError('No interior critical tax')
        central=np.float32(float(tax_critical))
        lo=np.nextafter(central,np.float32('-inf'))
        hi=np.nextafter(central,np.float32('inf'))
        left_mid=(mp.mpf(str(float(lo)))+mp.mpf(str(float(central))))/2
        right_mid=(mp.mpf(str(float(central)))+mp.mpf(str(float(hi))))/2
        radius=min(tax_critical-left_mid,right_mid-tax_critical)/3
        if radius<=0:raise ArithmeticError('Threshold too near FP32 rounding transition')
        tax_minus=tax_critical-radius
        tax_plus=tax_critical+radius
        def result(tax):
            t=1-tax
            b=(A+t*C/eta)/D
            net=(delta+alpha/m)*b-t*C-P/m
            recovery=alpha*b/P
            return {'tax':mp.nstr(tax,digits),'boundary':mp.nstr(b,digits),
                    'net_cashflow':mp.nstr(net,digits),
                    'local_log_curvature':mp.nstr(-2*net/sigma**2,digits),
                    'recovery_over_face':mp.nstr(recovery,digits),
                    'tax_fp32_hex':np.float32(float(tax)).tobytes().hex(),
                    'boundary_fp32_hex':np.float32(float(b)).tobytes().hex()}
        first,last=result(tax_minus),result(tax_plus)
        if not (mp.mpf(first['net_cashflow'])>0>mp.mpf(last['net_cashflow'])):
            raise ArithmeticError('Opposite local signs were not constructed')
        if (first['tax_fp32_hex']!=last['tax_fp32_hex'] or
                first['boundary_fp32_hex']!=last['boundary_fp32_hex']):
            raise ArithmeticError('No identical FP32 representation')
        return {
            'schema':'hcsn.p0-original-hx-fp32-local-obstacle-information-loss.v1',
            'parameters_except_tax':{k:v for k,v in asdict(p).items() if k!='tax'},
            'precision_decimal_digits':digits,
            'tax_zero_cashflow':mp.nstr(tax_critical,digits),
            'tax_fp32_quantization_ulp':str(float(hi-central)),
            'tax_pair_separation':mp.nstr(2*radius,digits),
            'positive_net_negative_curvature':first,
            'negative_net_positive_curvature':last,
            'same_fp32_inputs':True,
            'same_fp32_boundary':True,
            'original_hx_scoped_local_necessary_test':True,
            'original_hx_full_domain_certified':False,
            'outward_rounded_certificate':False,
            'p0_p6_scientific_gates':{f'P{i}':'OPEN' for i in range(7)},
            'production_activation':False,
            'preregistration':False,
            'independent_science_attested':False,
            'conclusion':('Any map using only the FP32-rounded input vector must return '
                          'one verdict for both opposite-sign local-boundary cases; '
                          'an FP64/interval fallback or refusal is required.'),
        }
