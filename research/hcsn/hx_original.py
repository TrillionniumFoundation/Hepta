"""He--Xiong (2012), Journal of Finance 67(2), eqs. (5)--(12).

Exact finite-maturity bond value Eq. (8), closed free-boundary Eq. (12),
and an independent Green-integral evaluation of the ORIGINAL coupled equity
ODE Eq. (11), using Eq. (8) as its nonlocal source.

This is *not* the paper's Appendix Eq. (A7) literal Laplace expression;
the Green formulation is an alternative semianalytic solution and its
quadrature is not a production per-neuron activation.

Paper: https://www.princeton.edu/~wxiong/papers/rollover.pdf
PDF printed pages 399-401, 417-422, visually verified 2026-10-31.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import math

from scipy.integrate import quad
from scipy.optimize import brentq
from scipy.special import log_ndtr, ndtr


@dataclass(frozen=True)
class HXParams:
    r: float = .08
    delta: float = .02
    sigma: float = .23
    alpha: float = .60  # liquidation recovery
    tax: float = .27  # debt tax benefit pi
    xi: float = 1.0  # liquidity shock intensity
    k: float = .01  # cost per liquidity shock
    maturity: float = 1.0
    coupon_total: float = 6.39  # total outstanding coupon C
    face_total: float = 61.68  # total outstanding face P

    def __post_init__(self):
        v = (self.r, self.delta, self.sigma, self.alpha, self.tax,
             self.xi, self.k, self.maturity, self.coupon_total, self.face_total)
        if (not all(math.isfinite(t) for t in v)
            or not .005 <= self.r <= .30
            or not .001 <= self.delta <= .20
            or not .03 <= self.sigma <= .75
            or not 0.0 <= self.alpha <= 1.0
            or not 0.0 <= self.tax < 1.0
            or not 0.0 <= self.xi <= 10.0
            or not 0.0 <= self.k <= .25
            or not .05 <= self.maturity <= 10.0
            or not 0 < self.coupon_total <= 500.0
            or not 0 < self.face_total <= 1000.0):
            raise ValueError('Outside finite exploratory HX reference domain')

    @property
    def lam(self):
        return self.r + self.xi * self.k

    @property
    def c(self):
        return self.coupon_total / self.maturity

    @property
    def p(self):
        return self.face_total / self.maturity

    @property
    def a(self):
        return (self.r-self.delta-.5*self.sigma**2)/self.sigma**2

    @property
    def z(self):
        return math.hypot(self.a, math.sqrt(2*self.r)/self.sigma)

    @property
    def zhat(self):
        return math.hypot(self.a, math.sqrt(2*self.lam)/self.sigma)

    @property
    def eta(self):
        return self.z-self.a

    @property
    def gamma(self):
        return self.z+self.a


def _expo_ndtr(log_amp: float, z: float) -> float:
    """Evaluate exp(log_amp)*Phi(z) without overflow/underflow to NaN."""
    exponent = log_amp + float(log_ndtr(z))
    if exponent > 690:
        raise ArithmeticError('Out of certified log-normal CDF evaluation range')
    return math.exp(exponent) if exponent > -745 else 0.0


def hitting_and_discounted_hitting(x: float, tau: float, p: HXParams):
    """Eq. (8),(9): F=P(hit in tau), G=E[exp(-lam*t_hit)1_hit].

    x=ln(V/VB)>=0. At boundary F=G=1 for positive tau.
    """
    if not math.isfinite(x) or x < 0 or not math.isfinite(tau) or not 0 <= tau <= p.maturity:
        raise ValueError('Invalid log state or maturity')
    if x == 0:
        return 1., 1.
    if tau == 0:
        return 0., 0.
    t = p.sigma * math.sqrt(tau)
    a,zh = p.a,p.zhat
    h1=(-x-a*p.sigma**2*tau)/t
    h2=(-x+a*p.sigma**2*tau)/t
    q1=(-x-zh*p.sigma**2*tau)/t
    q2=(-x+zh*p.sigma**2*tau)/t
    f=ndtr(h1)+_expo_ndtr(-2*a*x,h2)
    g=_expo_ndtr((-a+zh)*x,q1)+_expo_ndtr((-a-zh)*x,q2)
    if not (-1e-12 <= g <= f + 1e-12 <= 1.+2e-12):
        raise ArithmeticError(f'Invalid F/G first-passage probabilities: {f=} {g=}')
    return min(1., max(0.,float(f))),min(1.,max(0.,float(g)))


def bond_price_from_log(x:float, tau:float, boundary:float,p:HXParams) -> float:
    """Original paper Eq. (8). Default payoff alpha*VB/m; no arbitrary Put."""
    if not math.isfinite(boundary) or boundary<=0:
        raise ValueError('Boundary must be finite and positive')
    f,g=hitting_and_discounted_hitting(x,tau,p)
    c0=p.c/p.lam
    return (c0 + math.exp(-p.lam*tau)*(p.p-c0)*(1-f)
            + (p.alpha*boundary/p.maturity-c0)*g)


def _laplace_of_cdf(k:float, b:float,t:float) -> float:
    """Int_0^inf exp(-k*x) Phi((-x+b*t*t)/t) dx.

    For k near zero the removable singularity is handled by direct quadrature
    rather than subtracting nearly equal CDFs.
    """
    if abs(k) < 1e-5:
        return quad(lambda x:math.exp(-k*x)*ndtr((-x+b*t*t)/t),0,max(10.,12*t+abs(b)*t*t),
                    epsabs=1e-12,epsrel=1e-12)[0]
    numerator=(ndtr(b*t)-_expo_ndtr((.5*k*k-b*k)*t*t,(b-k)*t))
    return numerator/k


def hx_integrals(p:HXParams):
    """Independent closed analytic Laplace integrals of Eq. 8 F and G."""
    t=p.sigma*math.sqrt(p.maturity)
    f=(_laplace_of_cdf(p.eta,-p.a,t)+_laplace_of_cdf(p.gamma,p.a,t))
    g=(_laplace_of_cdf(p.z-p.zhat,-p.zhat,t)
       +_laplace_of_cdf(p.z+p.zhat,p.zhat,t))
    if f < -1e-10 or g < -1e-10 or g > f+1e-10:
        raise ArithmeticError(f'Invalid analytic integrals: {f=} {g=}')
    return f,g


def closed_boundary(p:HXParams) -> float:
    """Paper Eq. (12), evaluated with stable analytic CDF integrals.

    Integrals hx_integrals are I_F and I_G, so the paper's b(-a)+b(a)
    equals exp(-lam*m)*I_F and its B(-zhat)+B(zhat) equals I_G.
    """
    I_f,I_g=hx_integrals(p)
    c0=p.c/p.lam
    u=p.p-c0
    numerator=(((1-p.tax)*p.coupon_total +(1-math.exp(-p.lam*p.maturity))*u)/p.eta
               +math.exp(-p.lam*p.maturity)*u*I_f+c0*I_g)
    denominator=p.delta/(p.eta-1)+p.alpha/p.maturity*I_g
    if denominator <=0:
        raise ArithmeticError('No positive free-boundary denominator')
    vb=numerator/denominator
    if not math.isfinite(vb) or vb<=0:
        raise ValueError('No positive economically admissible HX boundary for given parameters')
    return vb


def running_reward(x:float,boundary:float,p:HXParams) -> float:
    v=boundary*math.exp(x)
    return (p.delta*v-(1-p.tax)*p.coupon_total
            +bond_price_from_log(x,p.maturity,boundary,p)-p.p)


def _rollover_forcing(x:float,boundary:float,p:HXParams) -> float:
    f,g=hitting_and_discounted_hitting(x,p.maturity,p)
    c0=p.c/p.lam
    return (-math.exp(-p.lam*p.maturity)*(p.p-c0)*f
            +(p.alpha*boundary/p.maturity-c0)*g)


def independent_boundary(p:HXParams) -> float:
    """Solve Eq. (11) smooth-pasting integral by independent adaptive quadrature.

    Bracketed root is deliberately independent of Eq. (12) algebra.
    """
    eta=p.eta
    upper=20.
    q=(1-p.tax)*p.coupon_total+(p.p-p.c/p.lam)*(-math.expm1(-p.lam*p.maturity))
    def condition(boundary):
        # Integrate the slow exp(-(eta-1)x) tail EXACTLY; only Gaussian
        # hitting terms require quadrature. Truncating the full f at x=25
        # biases the boundary by ~0.16 in the paper's baseline.
        analytic=p.delta*boundary/(eta-1)-q/eta
        rollover=quad(lambda x:math.exp(-eta*x)*_rollover_forcing(x,boundary,p),
                      0,upper,epsabs=1e-9,epsrel=1e-10,limit=220)[0]
        return analytic+rollover
    b1,b2=1e-3,1e5
    if not (condition(b1)<0<condition(b2)):
        raise ValueError('No smooth-pasting root in bracket')
    return brentq(condition,b1,b2,xtol=1e-10)


def equity_green(v:float,boundary:float,p:HXParams) -> float:
    """Original Eq. (11), independent Green representation, not A7 transcription.

    Imposes E(VB)=0 and upper no-explosive-homogeneous-mode condition.
    For v>=VB, the E(V) solution is linear at infinity; in the stopping
    region the equity payoff is zero.
    """
    if not math.isfinite(v) or v<=0 or boundary<=0 or not math.isfinite(boundary):
        raise ValueError('Invalid equity value or boundary')
    if v<=boundary:
        return 0.
    x=math.log(v/boundary)
    eta,gamma=p.eta,p.gamma
    diff=.5*p.sigma*p.sigma
    q=(1-p.tax)*p.coupon_total+(p.p-p.c/p.lam)*(-math.expm1(-p.lam*p.maturity))
    particular=(boundary*math.exp(x)-q/p.r
                -(boundary-q/p.r)*math.exp(-gamma*x))
    upper=max(18.,x+10.)
    # Gaussian-decaying rollover part. The slowly decaying affine forcing
    # is solved in closed form above, avoiding finite quadrature bias.
    left=quad(lambda y:math.exp(-gamma*x)*(math.exp(gamma*y)-math.exp(-eta*y))*
              _rollover_forcing(y,boundary,p),0,x,epsabs=2e-8,epsrel=2e-9,limit=250)[0]
    right=quad(lambda y:math.exp(eta*x-eta*y)*(-math.expm1(-(eta+gamma)*x))*
               _rollover_forcing(y,boundary,p),x,upper,epsabs=2e-8,epsrel=2e-9,limit=250)[0]
    return particular+(left+right)/(diff*(eta+gamma))


def equity_smooth_derivative_at_boundary(boundary:float,p:HXParams):
    """Independent one-sided derivative Green operator at x=0, per log V."""
    q=(1-p.tax)*p.coupon_total+(p.p-p.c/p.lam)*(-math.expm1(-p.lam*p.maturity))
    integral=(p.delta*boundary/(p.eta-1)-q/p.eta
              +quad(lambda x:math.exp(-p.eta*x)*_rollover_forcing(x,boundary,p),
                    0,20.,epsabs=1e-9,epsrel=1e-10,limit=240)[0])
    return integral/(.5*p.sigma**2)


def equity_pde_residual_fd(x:float,boundary:float,p:HXParams,step:float=.003):
    """Finite difference *probe* for Eq. (11) using Green solution.
    Not a standalone FD reference. 0<step<x; O(step^2) error.
    """
    if x <= step:
        raise ValueError('Probe must be inside continuation domain')
    e0=equity_green(boundary*math.exp(x),boundary,p)
    em=equity_green(boundary*math.exp(x-step),boundary,p)
    ep=equity_green(boundary*math.exp(x+step),boundary,p)
    der=(ep-em)/(2*step)
    curv=(ep-2*e0+em)/(step*step)
    nu=p.r-p.delta-.5*p.sigma**2
    return (.5*p.sigma**2*curv+nu*der-p.r*e0+running_reward(x,boundary,p))
