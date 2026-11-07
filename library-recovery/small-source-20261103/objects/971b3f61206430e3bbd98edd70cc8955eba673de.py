"""Finite-grid regenerative impulse-control QVI: independent exploratory model.

This is NOT the coupled He-Xiong financial solution. A bounded log-V
continuous-time Markov chain approximates a GBM generator; a reset impulse
returns to a fixed grid state and charges a fixed cost. Policy iteration solves
max{(Q-rI)U+f, U[j]-c-U[i]}=0. Reflecting truncation boundaries are explicit.
"""
from dataclasses import dataclass
import numpy as np
from scipy.sparse import diags, lil_matrix
from scipy.sparse.linalg import spsolve

@dataclass(frozen=True)
class QVIConfig:
    n:int=201
    xmin:float=-2.
    xmax:float=2.
    r:float=.1
    sigma:float=.3
    drift:float=0.
    reset_x:float=.7
    reset_cost:float=.15
    running_offset:float=.35
    max_iter:int=200

def build_generator(p:QVIConfig):
    if not(30<=p.n<=4001 and p.xmin<p.reset_x<p.xmax and
           0<p.r<2 and 0<p.sigma<=2 and p.reset_cost>0 and p.max_iter>0):
        raise ValueError('invalid bounded QVI parameters')
    xs=np.linspace(p.xmin,p.xmax,p.n)
    dx=xs[1]-xs[0]
    # Positive off-diagonals: first order upwind rates for drift and central diffusion.
    low=p.sigma**2/(2*dx**2)+max(-p.drift,0)/dx
    high=p.sigma**2/(2*dx**2)+max(p.drift,0)/dx
    Q=diags([np.full(p.n-1,low), np.full(p.n,-low-high),
             np.full(p.n-1,high)],[-1,0,1],format='lil')
    # Reflecting endpoints: remove rates to out-of-domain destinations.
    Q[0,0]=-high
    Q[-1,-1]=-low
    return xs,Q.tocsr(),int(np.argmin(abs(xs-p.reset_x)))

def solve_qvi(p:QVIConfig=QVIConfig()):
    xs,Q,j=build_generator(p)
    f=np.exp(xs)-p.running_offset
    # Do not intervene at reset index: an immediate reset would lose reset_cost.
    policy=np.zeros(p.n,dtype=bool)
    a=(p.r*diags(np.ones(p.n),0,format='csr')-Q).tolil()
    for it in range(p.max_iter):
        mat=a.copy(); rhs=f.copy()
        for i in np.flatnonzero(policy):
            mat.rows[i]=[int(i),int(j)] if i!=j else [int(i)]
            mat.data[i]=[1.,-1.] if i!=j else [1.]
            rhs[i]=-p.reset_cost
        u=np.asarray(spsolve(mat.tocsr(),rhs))
        if not np.all(np.isfinite(u)):raise ArithmeticError('nonfinite QVI solution')
        cont=f-(a@u)
        impulse=u[j]-p.reset_cost-u
        new=(impulse>cont+1e-10)
        new[j]=False
        if np.array_equal(policy,new):
            residual=np.maximum(cont,impulse)
            return {'xs':xs,'u':u,'reset_index':j,'policy':new,
                    'iterations':it+1,'residual_sup':float(abs(residual).max()),
                    'continuation':cont,'intervention':impulse,
                    'q':Q,'running_reward':f}
        policy=new
    raise RuntimeError('policy iteration did not converge')

def reset_path(p:QVIConfig, states):
    """Apply the solved threshold policy to a recorded sequence of state indices."""
    s=solve_qvi(p); j=s['reset_index']; out=[]
    for idx in states:
        if not 0<=idx<p.n:raise ValueError('index out of range')
        fired=bool(s['policy'][idx]); out.append((j if fired else idx,fired))
    return out
