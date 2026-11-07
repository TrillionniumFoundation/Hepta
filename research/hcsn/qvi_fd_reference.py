"""Independent finite-difference policy iteration for a regenerative GBM QVI.

NO analytical boundary, root, value, or equity formula is called to produce
this reference.  A sparse M-matrix discretization of the log-GBM generator
and an impulse operator U(R)-c are solved by policy iteration.  The reset
anchor R is represented exactly at a grid node; far-field U(V)~V-K is a
finite-domain asymptotic boundary, whose truncation error must be studied.

This is a finite-domain independent numerical reference, not a proof of a
global viscosity solution and not original He-Xiong financial economics.
"""
from __future__ import annotations
from dataclasses import dataclass
import math
import numpy as np
from scipy.sparse import lil_matrix
from scipy.sparse.linalg import spsolve

try:
    from .regenerative_qvi import RegenerativeParams
except ImportError:
    from regenerative_qvi import RegenerativeParams


@dataclass(frozen=True)
class QVIReference:
    x: np.ndarray
    v: np.ndarray
    u: np.ndarray
    intervention: np.ndarray
    reset_index: int
    estimated_boundary: float
    iterations: int
    max_complementarity_residual: float
    max_positive_branch: float
    max_negative_active_branch: float
    far_field: float


def _generator_coefficients(p: RegenerativeParams, dx: float):
    mu = p.r-p.delta-.5*p.sigma*p.sigma
    d = .5*p.sigma*p.sigma/dx**2
    if d < 0 or dx<=0:
        raise ValueError('invalid grid')
    # Centered drift where monotone; otherwise positive generator upwind.
    if abs(mu)*dx <= p.sigma*p.sigma:
        low, high = d-mu/(2*dx),d+mu/(2*dx)
    elif mu>=0:
        low, high = d,d+mu/dx
    else:
        low, high = d-mu/dx,d
    return float(low),float(high)


def solve_qvi_fd(p:RegenerativeParams, *, h:float=.025,
                 left_steps:int=220,right_steps:int=220,
                 max_iter:int=80) -> QVIReference:
    """Solve with policy iteration and a pinned reset grid node, no root hints.

    For each internal state choose either continuation row
       (r+a+b) U_i - a U_{i-1} -b U_{i+1} = delta*V_i-r*K
    or reset row U_i-U_R=-c.  Terminal top value approximates V-K.
    """
    if not (.005<=h<=.08) or left_steps<60 or right_steps<60 or max_iter<2:
        raise ValueError('Unsupported numerical reference domain')
    x=np.arange(-left_steps,right_steps+1,dtype=float)*h
    v=p.reset_value*np.exp(x)
    n=len(x);j=left_steps
    low,high=_generator_coefficients(p,h)
    # Initial policy independent of analytical trigger (simple threshold R/2).
    policy=v < .5*p.reset_value
    policy[0]=True
    policy[-1]=False
    policy[j]=False
    f=p.delta*v-p.r*p.k
    u=np.zeros(n,dtype=float)
    top=v[-1]-p.k
    for it in range(1,max_iter+1):
        a=lil_matrix((n,n),dtype=float)
        rhs=np.empty(n,dtype=float)
        # The entire lower boundary is within the immediate-reset region
        # in the accepted reference domain; every policy verify thereafter.
        for i in range(n):
            if i==n-1:
                a[i,i]=1.;rhs[i]=top
            elif i==0 or policy[i]:
                a[i,i]=1.;a[i,j]=-1.;rhs[i]=-p.reset_cost
            else:
                a[i,i]=p.r+low+high
                a[i,i-1]=-low
                a[i,i+1]=-high
                rhs[i]=f[i]
        u=np.asarray(spsolve(a.tocsr(),rhs),dtype=float)
        if not np.all(np.isfinite(u)):
            raise ArithmeticError('nonfinite independent QVI solver')
        g=np.zeros(n,dtype=float)
        g[1:-1]=low*u[:-2]-(p.r+low+high)*u[1:-1]+high*u[2:]+f[1:-1]
        obstacle=u[j]-p.reset_cost-u
        new=obstacle >= g
        new[0]=True
        new[-1]=False
        new[j]=False
        if np.array_equal(new,policy):
            break
        policy=new
    else:
        raise RuntimeError('QVI policy iteration not converged')
    g=np.zeros(n,dtype=float)
    g[1:-1]=low*u[:-2]-(p.r+low+high)*u[1:-1]+high*u[2:]+f[1:-1]
    obstacle=u[j]-p.reset_cost-u
    residual=np.maximum(g[1:-1],obstacle[1:-1])
    max_r=float(np.max(abs(residual)))
    max_positive=float(max(np.max(g[1:-1]),np.max(obstacle[1:-1])))
    active=np.where(policy[1:-1],obstacle[1:-1],g[1:-1])
    max_active=float(np.max(abs(active)))
    if max_r>1e-6*max(1.,float(np.max(abs(u)))):
        raise ArithmeticError(f'Incomplete numerical QVI: {max_r}')
    # One-sided boundary estimate; lower bracket is the greatest reset node.
    trigger=np.where(policy[:-1] & ~policy[1:])[0]
    if len(trigger)!=1 or not (0<trigger[0]<j):
        raise ArithmeticError('No unique lower intervention region in grid')
    lower=trigger[0]
    # Midpoint in geometric/log scale, NOT using analytic root.
    b=math.sqrt(v[lower]*v[lower+1])
    return QVIReference(x,v,u,policy,j,b,it,max_r,max_positive,max_active,float(top))
