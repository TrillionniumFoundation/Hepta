"""Independent numerical audit of original He--Xiong Eq8/11/12/A7 plus a separate fixed-reset QVI.

This module deliberately imports no research.hcsn implementation. It
reconstructs Eq8 first-passage factors, obtains Eq12 from direct Laplace
quadrature, obtains Eq11's smooth-fit root from an independently integrated
forcing equation, and evaluates literal Appendix A7 against a Green integral.
It also reproduces a frozen FP32 information-loss witness at MP60 and solves
one separate fixed-reset GBM QVI by sparse policy iteration.

Finite-domain numerical cross-check only. Not an all-domain proof, external
attestation, trained HCSN result, or production qualification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import json
import math
import platform
import sys
from pathlib import Path

import mpmath as mp
import numpy as np
import scipy
from scipy.integrate import quad
from scipy.optimize import brentq
from scipy.sparse import lil_matrix
from scipy.sparse.linalg import spsolve
from scipy.special import log_ndtr, ndtr


@dataclass(frozen=True)
class HX:
    r: float
    delta: float
    sigma: float
    alpha: float
    tax: float
    xi: float
    k: float
    maturity: float
    coupon: float
    face: float

    @property
    def lam(self): return self.r + self.xi * self.k
    @property
    def c(self): return self.coupon / self.maturity
    @property
    def p(self): return self.face / self.maturity
    @property
    def a(self): return (self.r - self.delta - .5*self.sigma**2) / self.sigma**2
    @property
    def z(self): return math.hypot(self.a, math.sqrt(2*self.r)/self.sigma)
    @property
    def zhat(self): return math.hypot(self.a, math.sqrt(2*self.lam)/self.sigma)
    @property
    def eta(self): return self.z - self.a
    @property
    def gamma(self): return self.z + self.a


def _exp_phi(log_amp: float, z: float) -> float:
    q = log_amp + float(log_ndtr(z))
    if q > 700:
        raise ArithmeticError("normal-CDF product exceeds finite reference range")
    return math.exp(q) if q > -745 else 0.0


def _fg(x: float, p: HX) -> tuple[float, float]:
    """Original Eq8 first-passage F and discounted G, independently coded."""
    if x < 0 or not math.isfinite(x):
        raise ValueError("invalid log distance")
    if x == 0:
        return 1.0, 1.0
    t = p.sigma * math.sqrt(p.maturity)
    a, zhat = p.a, p.zhat
    h1 = (-x-a*p.sigma**2*p.maturity)/t
    h2 = (-x+a*p.sigma**2*p.maturity)/t
    q1 = (-x-zhat*p.sigma**2*p.maturity)/t
    q2 = (-x+zhat*p.sigma**2*p.maturity)/t
    f = float(ndtr(h1)) + _exp_phi(-2*a*x, h2)
    g = (_exp_phi((-a+zhat)*x, q1)
         + _exp_phi((-a-zhat)*x, q2))
    if not (-1e-12 <= g <= f+1e-12 <= 1+2e-12):
        raise ArithmeticError(f"invalid first-passage pair F={f}, G={g}")
    return min(1.0, max(0.0, f)), min(1.0, max(0.0, g))


def _laplace_fg(p: HX) -> tuple[float, float]:
    eta = p.eta
    f = quad(lambda x: math.exp(-eta*x)*_fg(x,p)[0], 0, math.inf,
             epsabs=2e-12, epsrel=2e-12, limit=300)[0]
    g = quad(lambda x: math.exp(-eta*x)*_fg(x,p)[1], 0, math.inf,
             epsabs=2e-12, epsrel=2e-12, limit=300)[0]
    if not (0 <= g <= f+1e-10):
        raise ArithmeticError("invalid direct Laplace integrals")
    return f, g


def _eq12_boundary(p: HX, IF: float, IG: float) -> float:
    c0 = p.c/p.lam
    u = p.p-c0
    ell = math.exp(-p.lam*p.maturity)
    q = (1-p.tax)*p.coupon + (1-ell)*u
    numerator = q/p.eta + ell*u*IF + c0*IG
    denominator = p.delta/(p.eta-1) + p.alpha/p.maturity*IG
    if denominator <= 0:
        raise ArithmeticError("nonpositive Eq12 denominator")
    b = numerator/denominator
    if not math.isfinite(b) or b <= 0:
        raise ArithmeticError("nonpositive Eq12 candidate")
    return b


def _eq11_smoothfit_root(p: HX) -> float:
    """Direct adaptive integral of the original Eq11 smooth-fit condition."""
    c0 = p.c/p.lam
    u = p.p-c0
    ell = math.exp(-p.lam*p.maturity)
    q = (1-p.tax)*p.coupon + (1-ell)*u

    def residual(boundary: float) -> float:
        affine = p.delta*boundary/(p.eta-1) - q/p.eta
        rollover = quad(
            lambda x: math.exp(-p.eta*x) * (
                -ell*u*_fg(x,p)[0]
                + (p.alpha*boundary/p.maturity-c0)*_fg(x,p)[1]),
            0, math.inf, epsabs=1e-11, epsrel=1e-10, limit=300
        )[0]
        return affine + rollover

    lo, hi = 1e-4, 1e5
    if not residual(lo) < 0 < residual(hi):
        raise ArithmeticError("independent Eq11 root not bracketed")
    return brentq(residual, lo, hi, xtol=1e-11, rtol=1e-12)


def _bond_eq8(x: float, boundary: float, p: HX) -> float:
    f, g = _fg(x,p)
    c0 = p.c/p.lam
    return (c0 + math.exp(-p.lam*p.maturity)*(p.p-c0)*(1-f)
            + (p.alpha*boundary/p.maturity-c0)*g)


def _forcing_eq11(x: float, boundary: float, p: HX) -> float:
    f, g = _fg(x,p)
    c0 = p.c/p.lam
    u = p.p-c0
    return (-math.exp(-p.lam*p.maturity)*u*f
            + (p.alpha*boundary/p.maturity-c0)*g)


def _green_eq11(v: float, boundary: float, p: HX) -> float:
    if v <= boundary:
        return 0.0
    x = math.log(v/boundary)
    eta, gamma = p.eta, p.gamma
    diffusion = .5*p.sigma*p.sigma
    c0 = p.c/p.lam
    u = p.p-c0
    q = ((1-p.tax)*p.coupon
         + u*(-math.expm1(-p.lam*p.maturity)))
    particular = (boundary*math.exp(x)-q/p.r
                  -(boundary-q/p.r)*math.exp(-gamma*x))
    upper = max(18.0, x+10.0)
    left = quad(
        lambda y: math.exp(-gamma*x)*(math.exp(gamma*y)-math.exp(-eta*y))
                  *_forcing_eq11(y,boundary,p),
        0, x, epsabs=2e-11, epsrel=2e-10, limit=250
    )[0]
    right = quad(
        lambda y: math.exp(eta*x-eta*y)*(-math.expm1(-(eta+gamma)*x))
                  *_forcing_eq11(y,boundary,p),
        x, upper, epsabs=2e-11, epsrel=2e-10, limit=250
    )[0]
    return particular+(left+right)/(diffusion*(eta+gamma))


def _K_a7(v: float, p: HX, w: float, h: float) -> float:
    t = p.sigma*math.sqrt(p.maturity)
    shift = h-p.a
    logm = .5*(shift*shift-w*w)*t*t
    first = (float(ndtr(w*t))-_exp_phi(logm,shift*t))*math.exp(-h*v)
    second = _exp_phi(logm-h*v,(-v+shift*t*t)/t)
    third = _exp_phi(-(p.a+w)*v,(-v+w*t*t)/t)
    return first+second-third


def _k_a7(v: float, p: HX, w: float) -> float:
    t = p.sigma*math.sqrt(p.maturity)
    shift = -p.eta-p.a
    logm = .5*(shift*shift-w*w)*t*t
    return (_exp_phi(logm+p.eta*v,(-v+shift*t*t)/t)
            -_exp_phi(-(p.a+w)*v,(-v+w*t*t)/t))


def _A_a7(v: float, p: HX, y: float) -> float:
    z = p.z
    if abs(z-y) < 1e-7:
        raise ArithmeticError("literal A7 direct form singular")
    return ((_K_a7(v,p,y,p.gamma)+_k_a7(v,p,-y))/(z-y)
            +(_K_a7(v,p,-y,p.gamma)+_k_a7(v,p,y))/(z+y))


def _literal_a7(v: float, boundary: float, p: HX) -> float:
    if v <= boundary:
        return 0.0
    x = math.log(v/boundary)
    z, gamma, eta = p.z, p.gamma, p.eta
    c0 = p.c/p.lam
    u = p.p-c0
    h = ((1-p.tax)*p.coupon
         +(-math.expm1(-p.lam*p.maturity))*u)
    s2 = p.sigma*p.sigma
    return (
        v
        - p.delta*boundary*math.exp(-gamma*x)/(z*s2*(gamma+1))
        - h/(z*s2)*(1/eta+(-math.expm1(-gamma*x))/gamma)
        + (math.exp(-p.lam*p.maturity)*u*_A_a7(x,p,p.a)
           -(p.alpha*boundary/p.maturity-c0)*_A_a7(x,p,p.zhat))/(z*s2)
    )


def _hx_panel() -> dict:
    baseline = HX(.08,.02,.23,.60,.27,1.0,.01,1.0,6.39,61.68)
    rng = np.random.default_rng(20261106)
    rows = []
    rejected = 0
    attempts = 0
    while len(rows) < 40 and attempts < 200:
        attempts += 1
        r = float(rng.uniform(.03,.18))
        delta = float(rng.uniform(.005,min(.08,r-.005)))
        p = HX(r,delta,float(rng.uniform(.08,.50)),
               float(rng.uniform(.10,.95)),float(rng.uniform(.02,.65)),
               float(rng.uniform(.20,5.0)),float(rng.uniform(.01,.18)),
               float(rng.uniform(.20,5.0)),float(rng.uniform(1,80)),
               float(rng.uniform(10,250)))
        try:
            IF, IG = _laplace_fg(p)
            b12 = _eq12_boundary(p,IF,IG)
            b11 = _eq11_smoothfit_root(p)
            errors = []
            for x in (1e-3,.03,.3,1.5,4.0):
                v = b12*math.exp(x)
                a7 = _literal_a7(v,b12,p)
                green = _green_eq11(v,b12,p)
                errors.append(abs(a7-green)/max(1.0,abs(green)))
            rows.append({
                "parameters": asdict(p),
                "eq12_boundary": b12,
                "independent_eq11_boundary": b11,
                "boundary_relative_error": abs(b12-b11)/max(1.0,abs(b12)),
                "a7_vs_green_relative_errors": errors,
                "max_a7_vs_green_relative_error": max(errors),
                "IF_direct": IF,
                "IG_direct": IG,
            })
        except (ArithmeticError, ValueError, OverflowError, ZeroDivisionError):
            rejected += 1
    if len(rows) != 40:
        raise RuntimeError(f"only {len(rows)} admissible panel rows in {attempts} attempts")

    IF,IG = _laplace_fg(baseline)
    b = _eq12_boundary(baseline,IF,IG)
    baseline_rows = []
    for x in (1e-4,1e-3,.01,.1,1.,3.,8.):
        v=b*math.exp(x)
        a7=_literal_a7(v,b,baseline)
        green=_green_eq11(v,b,baseline)
        baseline_rows.append({
            "log_margin":x,"a7":a7,"green":green,
            "absolute_error":abs(a7-green),
            "relative_error":abs(a7-green)/max(1.0,abs(green))
        })
    return {
        "baseline": {"parameters":asdict(baseline),"boundary_eq12":b,
                     "boundary_eq11_direct":_eq11_smoothfit_root(baseline),
                     "points":baseline_rows},
        "random_panel_seed": "20261106",
        "accepted_rows": len(rows),
        "attempts": attempts,
        "rejected_candidates": rejected,
        "max_boundary_relative_error": max(x["boundary_relative_error"] for x in rows),
        "max_a7_green_relative_error": max(x["max_a7_vs_green_relative_error"] for x in rows),
        "rows": rows,
    }


def _fp32_pair_mp60() -> dict:
    with mp.workdps(60):
        r=mp.mpf(".10"); delta=mp.mpf(".075"); sigma=mp.mpf(".20")
        alpha=mp.mpf(".40"); xi=mp.mpf("4."); k=mp.mpf(".20")
        maturity=mp.mpf("3."); coupon=mp.mpf("5."); face=mp.mpf("20.")
        taxes=[mp.mpf("0.39990773048821086366402572931572947159497055383133"),
               mp.mpf("0.39990773790723072732805145863145894318994110766265")]
        lam=r+xi*k
        a=(r-delta-sigma**2/2)/sigma**2
        eta=mp.sqrt(a*a+2*r/sigma**2)-a
        zhat=mp.sqrt(a*a+2*lam/sigma**2)
        t=sigma*mp.sqrt(maturity)
        Phi=lambda z:mp.erfc(-z/mp.sqrt(2))/2
        def F(x):
            return (Phi((-x-a*sigma*sigma*maturity)/t)
                    +mp.exp(-2*a*x)*Phi((-x+a*sigma*sigma*maturity)/t))
        def G(x):
            return (mp.exp((-a+zhat)*x)*Phi((-x-zhat*sigma*sigma*maturity)/t)
                    +mp.exp((-a-zhat)*x)*Phi((-x+zhat*sigma*sigma*maturity)/t))
        split=[0,mp.mpf(".1"),mp.mpf(".5"),1,2,5,10,mp.inf]
        IF=mp.quad(lambda x:mp.exp(-eta*x)*F(x),split)
        IG=mp.quad(lambda x:mp.exp(-eta*x)*G(x),split)
        c0=(coupon/maturity)/lam
        u=face/maturity-c0
        ell=mp.exp(-lam*maturity)
        A=(1-ell)*u/eta+ell*u*IF+c0*IG
        D=delta/(eta-1)+alpha/maturity*IG
        rows=[]
        for tax in taxes:
            boundary=(A+(1-tax)*coupon/eta)/D
            qB=(delta+alpha/maturity)*boundary-(1-tax)*coupon-face/maturity
            rows.append({
                "tax":mp.nstr(tax,55),
                "boundary":mp.nstr(boundary,55),
                "boundary_cashflow_qB":mp.nstr(qB,55),
                "local_log_curvature":mp.nstr(-2*qB/sigma**2,55),
                "tax_fp32_bits":np.float32(float(tax)).tobytes().hex(),
                "boundary_fp32_bits":np.float32(float(boundary)).tobytes().hex(),
                "recovery_over_face":mp.nstr(alpha*boundary/face,30),
            })
        return {
            "precision_digits":60,
            "tax_pair":rows,
            "same_fp32_tax_bits":rows[0]["tax_fp32_bits"]==rows[1]["tax_fp32_bits"],
            "same_fp32_boundary_bits":rows[0]["boundary_fp32_bits"]==rows[1]["boundary_fp32_bits"],
            "opposite_qB_signs":float(rows[0]["boundary_cashflow_qB"])*float(rows[1]["boundary_cashflow_qB"])<0,
            "interpretation":"FP32-only input cannot distinguish opposite original Eq11 local signs; use higher-precision inputs, certified interval fallback, or refusal.",
        }


def _gamma_root(r:float,delta:float,sigma:float)->float:
    mu=r-delta-.5*sigma*sigma
    disc=math.hypot(mu,math.sqrt(2*r)*sigma)
    return 2*r/(disc-mu) if mu<0 else (disc+mu)/(sigma*sigma)


def _analytic_reset_boundary(r:float,delta:float,sigma:float,R:float,c:float)->float:
    g=_gamma_root(r,delta,sigma)
    def f(b):
        return g*(R-b-c)-b*(1-math.exp(-g*math.log(R/b)))
    return brentq(f,1e-12,R-c-1e-12,xtol=1e-14,rtol=8*np.finfo(float).eps)


def _analytic_reset_value(v:float,r:float,delta:float,sigma:float,K:float,R:float,c:float)->float:
    b=_analytic_reset_boundary(r,delta,sigma,R,c)
    g=_gamma_root(r,delta,sigma)
    return b-K+b/g if v<=b else v-K+(b/g)*math.exp(-g*math.log(v/b))


def _qvi_fd(r:float,delta:float,sigma:float,K:float,R:float,c:float,h:float,steps:int)->dict:
    """Independent sparse policy iteration for max[(L-r)U+f,U(R)-c-U]=0."""
    mu=r-delta-.5*sigma*sigma
    D=.5*sigma*sigma
    x=np.arange(-steps,steps+1,dtype=float)*h
    v=R*np.exp(x); n=len(x); j=steps
    d=D/(h*h)
    if abs(mu)*h<=sigma*sigma:
        low,high=d-mu/(2*h),d+mu/(2*h)
    elif mu>=0:
        low,high=d,d+mu/h
    else:
        low,high=d-mu/h,d
    reward=delta*v-r*K
    policy=v<.5*R
    policy[0]=True; policy[-1]=False; policy[j]=False
    for iteration in range(1,101):
        matrix=lil_matrix((n,n),dtype=float); rhs=np.empty(n)
        for i in range(n):
            if i==n-1:
                matrix[i,i]=1.0; rhs[i]=v[-1]-K
            elif i==0 or policy[i]:
                matrix[i,i]=1.0; matrix[i,j]=-1.0; rhs[i]=-c
            else:
                matrix[i,i]=r+low+high
                matrix[i,i-1]=-low; matrix[i,i+1]=-high
                rhs[i]=reward[i]
        value=np.asarray(spsolve(matrix.tocsr(),rhs),dtype=float)
        continuation=np.zeros(n)
        continuation[1:-1]=(low*value[:-2]-(r+low+high)*value[1:-1]
                            +high*value[2:]+reward[1:-1])
        impulse=value[j]-c-value
        new=impulse>=continuation
        new[0]=True; new[-1]=False; new[j]=False
        if np.array_equal(new,policy):
            break
        policy=new
    else:
        raise RuntimeError("independent QVI policy iteration did not converge")
    continuation=np.zeros(n)
    continuation[1:-1]=(low*value[:-2]-(r+low+high)*value[1:-1]
                        +high*value[2:]+reward[1:-1])
    impulse=value[j]-c-value
    residual=float(np.max(np.abs(np.maximum(continuation[1:-1],impulse[1:-1]))))
    active=np.where(policy[1:-1],impulse[1:-1],continuation[1:-1])
    active_res=float(np.max(np.abs(active)))
    crossings=np.where(policy[:-1] & ~policy[1:])[0]
    if len(crossings)!=1:
        raise ArithmeticError("QVI policy does not have one lower intervention boundary")
    idx=int(crossings[0])
    bfd=math.sqrt(v[idx]*v[idx+1])
    exact_boundary=_analytic_reset_boundary(r,delta,sigma,R,c)
    exact_values=np.array([_analytic_reset_value(float(z),r,delta,sigma,K,R,c) for z in v])
    interior=slice(2,-2)
    return {
        "h":h,"grid_points":n,"policy_iterations":iteration,
        "boundary_fd":bfd,"boundary_analytic":exact_boundary,
        "boundary_abs_error":abs(bfd-exact_boundary),
        "max_complementarity_residual":residual,
        "max_active_branch_residual":active_res,
        "max_value_abs_error":float(np.max(np.abs(value[interior]-exact_values[interior]))),
        "mean_value_abs_error":float(np.mean(np.abs(value[interior]-exact_values[interior]))),
        "far_field_value":float(v[-1]-K),
    }


def run_audit() -> dict:
    hx=_hx_panel()
    fp32=_fp32_pair_mp60()
    qvi_params={"r":.05,"delta":.03,"sigma":.2,"K":1.,"R":2.,"c":.2}
    qvi=[
        _qvi_fd(**qvi_params,h=.04,steps=140),
        _qvi_fd(**qvi_params,h=.02,steps=280),
        _qvi_fd(**qvi_params,h=.01,steps=560),
    ]
    if not (fp32["same_fp32_tax_bits"] and fp32["same_fp32_boundary_bits"] and fp32["opposite_qB_signs"]):
        raise AssertionError("frozen FP32 information-loss witness did not reproduce")
    if not (hx["max_boundary_relative_error"]<1e-9 and hx["max_a7_green_relative_error"]<1e-8):
        raise AssertionError("original HX Eq8/11/12/A7 independent panel mismatch")
    if not (qvi[2]["boundary_abs_error"]<qvi[1]["boundary_abs_error"]<qvi[0]["boundary_abs_error"]):
        raise AssertionError("QVI boundary mesh refinement did not improve")
    if not (qvi[2]["max_value_abs_error"]<qvi[1]["max_value_abs_error"]<qvi[0]["max_value_abs_error"]):
        raise AssertionError("QVI value mesh refinement did not improve")
    if max(x["max_complementarity_residual"] for x in qvi)>1e-7:
        raise AssertionError("QVI complementarity residual too large")
    return {
        "schema":"hcsn.p0-independent-eq8-eq11-eq12-a7-qvi.v1",
        "runtime":{"python":sys.version.split()[0],"numpy":np.__version__,
                   "scipy":scipy.__version__,"mpmath":mp.__version__,
                   "platform":platform.platform()},
        "original_hx":hx,
        "fp32_information_loss":fp32,
        "separate_fixed_reset_qvi":{
            "model":"GBM fixed-reset impulse QVI; explicitly NOT the original He-Xiong coupled financial obstacle/QVI",
            "parameters":qvi_params,"mesh_results":qvi,
            "boundary_refinement_monotone":True,"value_refinement_monotone":True,
        },
        "gates":{f"P{i}":"OPEN" for i in range(7)},
        "external_scientific_attestation":False,
        "full_original_hx_domain_proved":False,
        "original_hx_low_precision_certified":False,
        "general_endogenous_qvi_proved":False,
        "production_activation":False,
        "limitations":[
            "The 40-row HX panel is a deterministic finite sample, not the full legal parameter domain.",
            "Direct SciPy quadrature and the A7/Green agreement are numerical cross-checks, not outward-rounded global error certificates.",
            "The FP32 pair is a local information-loss counterexample, not a universal precision theorem.",
            "The fixed-reset QVI is a separate model and does not prove the original He-Xiong endogenous QVI.",
            "No external scientific trust-root signature, learned HCSN training result, multimodal heldout, target CPU/GPU energy, or medium-model quality-cost frontier is supplied."
        ],
    }


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    result=run_audit()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2,sort_keys=True,allow_nan=False)
        f.write("\n")
    print(json.dumps({
        "schema":result["schema"],
        "hx_rows":result["original_hx"]["accepted_rows"],
        "max_eq12_eq11_relative_error":result["original_hx"]["max_boundary_relative_error"],
        "max_a7_green_relative_error":result["original_hx"]["max_a7_green_relative_error"],
        "fp32_same_tax":result["fp32_information_loss"]["same_fp32_tax_bits"],
        "fp32_same_boundary":result["fp32_information_loss"]["same_fp32_boundary_bits"],
        "fp32_opposite_signs":result["fp32_information_loss"]["opposite_qB_signs"],
        "qvi_boundary_errors":[x["boundary_abs_error"] for x in result["separate_fixed_reset_qvi"]["mesh_results"]],
        "qvi_value_errors":[x["max_value_abs_error"] for x in result["separate_fixed_reset_qvi"]["mesh_results"]],
        "gates":result["gates"],
        "production_activation":False,
        "output":str(args.output),
    },indent=2,sort_keys=True))


if __name__=="__main__":
    main()
