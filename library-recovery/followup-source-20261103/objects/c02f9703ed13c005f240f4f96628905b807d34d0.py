"""Independent reference for a simplified perpetual GBM stopping kernel.
NOT the full He-Xiong (2012) rollover / debt-pricing model.
"""
from dataclasses import dataclass
import math
import numpy as np

@dataclass(frozen=True)
class Params:
    mu: float = 0.02
    sigma: float = 0.25
    rho: float = 0.08
    strike: float = 1.0
    def validate(self):
        if not all(map(math.isfinite,(self.mu,self.sigma,self.rho,self.strike))):
            raise ValueError('finite parameters required')
        if self.sigma <= 0 or self.rho <= 0 or self.strike <= 0 or self.rho <= self.mu:
            raise ValueError('require sigma>0, rho>max(mu,0), strike>0')


def roots(p):
    p.validate()
    b=p.mu-0.5*p.sigma*p.sigma
    d=math.sqrt(b*b+2*p.rho*p.sigma*p.sigma)
    return 2*p.rho/(d+b), -2*p.rho/(d-b)  # stable positive/negative characteristic roots


def analytic_call(s,p):
    pos,_=roots(p)
    boundary=pos*p.strike/(pos-1)
    s=np.asarray(s,dtype=float)
    return np.where(s>=boundary,s-p.strike,(boundary-p.strike)*np.power(s/boundary,pos))


def analytic_put(s,p):
    _,neg=roots(p)
    boundary=neg*p.strike/(neg-1)
    s=np.asarray(s,dtype=float)
    return np.where(s<=boundary,p.strike-s,(p.strike-boundary)*np.power(s/boundary,neg))


def fd_obstacle(p,kind='call',n=260,smin=0.025,smax=12.,tol=1e-9,max_iter=40000):
    """Projected SOR on log-state grid for max((L-rho)V, payoff-V)=0.
    Boundaries supplied by asymptotic exercise conditions, independent of optimal threshold.
    """
    p.validate()
    if kind not in ('call','put'): raise ValueError('kind')
    x=np.linspace(math.log(smin),math.log(smax),n+1)
    s=np.exp(x); h=x[1]-x[0]
    reward=np.maximum(s-p.strike,0) if kind=='call' else np.maximum(p.strike-s,0)
    a=0.5*p.sigma**2/h**2-(p.mu-0.5*p.sigma**2)/(2*h)
    c=0.5*p.sigma**2/h**2+(p.mu-0.5*p.sigma**2)/(2*h)
    diag=p.sigma**2/h**2+p.rho
    if min(a,c)<0: raise ValueError('mesh not monotone: refine grid')
    v=reward.copy()
    v[0]=0 if kind=='call' else p.strike-s[0]
    v[-1]=s[-1]-p.strike if kind=='call' else 0
    for step in range(max_iter):
        maxchange=0.
        for i in range(1,n):
            val=max(reward[i],(a*v[i-1]+c*v[i+1])/diag)
            maxchange=max(maxchange,abs(val-v[i]))
            v[i]=val
        if maxchange<tol: break
    else: raise RuntimeError('projected solver failed to converge')
    return s,v,step+1


def qvi_one_state(value, continue_value, reset_value, reset_cost):
    """One Bellman obstacle/QVI projection, not a full endogenous regeneration solver."""
    if reset_cost<0 or not all(map(math.isfinite,(value,continue_value,reset_value,reset_cost))):
        raise ValueError('invalid inputs')
    return max(continue_value, reset_value-reset_cost)


def check():
    tests=[Params(mu=0.02,sigma=0.25,rho=0.08),Params(mu=-0.02,sigma=0.32,rho=0.09)]
    report=[]
    for p in tests:
        pos,neg=roots(p)
        assert pos>1 and neg<0
        bc=pos*p.strike/(pos-1); bp=neg*p.strike/(neg-1)
        assert abs((bc-p.strike)*pos/bc-1)<1e-10
        assert abs((p.strike-bp)*neg/bp+1)<1e-10
        for kind,func in [('call',analytic_call),('put',analytic_put)]:
            s,v,its=fd_obstacle(p,kind)
            expected=func(s,p)
            mask=(s>0.15)&(s<6)
            err=float(np.max(np.abs(v[mask]-expected[mask])))
            assert err<0.012,(kind,err)
            assert np.all(v>=np.maximum(s-p.strike,0)-1e-10) if kind=='call' else np.all(v>=np.maximum(p.strike-s,0)-1e-10)
            report.append((p.mu,p.sigma,p.rho,kind,err,its))
    assert qvi_one_state(1.,0.6,1.2,0.1)==1.0999999999999999
    return report

if __name__=='__main__':
    for row in check(): print('mu=%g sigma=%g rho=%g kind=%s max_abs_error=%.6g iterations=%d'%row)
    print('PASS: simplified GBM analytic vs independent projected finite difference')
