"""P0 research: *new* state-dependent nonlocal impulse-reset HCSN QVI.

NOT part of He--Xiong (2012). Solves a genuine nonlocal obstacle, where
   M U(v) = U(R(v)) - c(v)
with bounded state-dependent reset target R(v), reset cost c(v), and
continuous-time GBM generator. Finite-domain numerical solution only.

Uses monotone finite differences (upwind if Peclet needs it), piecewise-
linear reset interpolation and policy iteration without any analytical
boundary as initialisation. Both branches are checked for complementarity.
No claim of formal proof or all-domain certified global optimality.
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
class ContextualReset:
    """Locally state-conditioned nonlocal reset, bounded to a fixed scale."""
    rho: float = .12
    cost_slope: float = .01

    def __post_init__(self):
        if not (math.isfinite(self.rho) and math.isfinite(self.cost_slope)
                and 0 <= self.rho <= .3 and 0 <= self.cost_slope <= .06):
            raise ValueError('Outside explored state-dependent reset domain')

    def target_and_cost(self, v: np.ndarray, p: RegenerativeParams):
        margin = np.log(v / p.reset_value)
        target = p.reset_value * (1 + self.rho * np.tanh(margin))
        cost = p.reset_cost + self.cost_slope * np.maximum(0, -margin)
        return target, cost


@dataclass(frozen=True)
class ContextualQVIResult:
    v: np.ndarray
    u: np.ndarray
    reset_policy: np.ndarray
    target: np.ndarray
    cost: np.ndarray
    estimated_trigger: float
    iterations: int
    max_complementarity_residual: float
    max_branch_violation: float
    source_generator: np.ndarray
    source_obstacle: np.ndarray


def _interpolants(v: np.ndarray, target: np.ndarray):
    if not np.all(np.isfinite(target)) or np.any(target <= v[0]) or np.any(target >= v[-1]):
        raise ValueError('Reset target outside numerical domain')
    right = np.searchsorted(v, target, side='right').clip(1, len(v)-1)
    left = right-1
    fraction = (target-v[left])/(v[right]-v[left])
    return left, right, fraction


def solve_contextual_qvi(p: RegenerativeParams,
                         cfg: ContextualReset = ContextualReset(), *,
                         h: float = .035,
                         left_steps: int = 165,
                         right_steps: int = 165,
                         max_iter: int = 100) -> ContextualQVIResult:
    """Grid-based impulse-control QVI, with nonlocal state-conditioned reset.

    Continuation: (L-r)U + delta*v-r*k = 0.  Reset: U=M U.
    For rows under reset policy, interpolation of U(target(v)) is inside the
    linear system; this is a true implicit impulse operator, not a posthoc gate.
    """
    if not (.012 <= h <= .065 and 90 <= left_steps <= 350
            and 90 <= right_steps <= 350 and 2 <= max_iter <= 200):
        raise ValueError('Outside numerical-solver grid budget')
    x = np.arange(-left_steps, right_steps + 1, dtype=float)*h
    v = p.reset_value * np.exp(x)
    n=len(v)
    reset_target, reset_cost = cfg.target_and_cost(v, p)
    li, ri, w = _interpolants(v, reset_target)
    i_reset=left_steps
    mu = p.r-p.delta-.5*p.sigma*p.sigma
    diffusion = .5*p.sigma*p.sigma/(h*h)
    if abs(mu)*h <= p.sigma*p.sigma:
        below,above=diffusion-mu/(2*h),diffusion+mu/(2*h)
    elif mu>=0:
        below,above=diffusion,diffusion+mu/h
    else:
        below,above=diffusion-mu/h,diffusion
    assert below >= 0 and above >= 0
    source=p.delta*v-p.r*p.k
    policy = v < p.reset_value*.45
    policy[0]=True; policy[-1]=False; policy[i_reset]=False
    u=np.zeros(n)
    for iterations in range(1,max_iter+1):
        mat=lil_matrix((n,n),dtype=float)
        rhs=np.zeros(n)
        for i in range(n):
            if i == n-1:
                mat[i,i]=1; rhs[i]=v[i]-p.k
            elif i==0 or policy[i]:
                mat[i,i]=1.
                mat[i,int(li[i])]-=(1-w[i])
                mat[i,int(ri[i])]-=w[i]
                rhs[i]=-reset_cost[i]
            else:
                mat[i,i]=p.r+below+above
                mat[i,i-1]=-below
                mat[i,i+1]=-above
                rhs[i]=source[i]
        u=np.asarray(spsolve(mat.tocsr(),rhs),dtype=float)
        if not np.all(np.isfinite(u)):
            raise ArithmeticError('Nonfinite contextual QVI value')
        gen = np.zeros(n)
        gen[1:-1]=below*u[:-2]-(p.r+below+above)*u[1:-1]+above*u[2:]+source[1:-1]
        obstacle=(1-w)*u[li]+w*u[ri]-reset_cost-u
        next_policy=obstacle>=gen
        next_policy[0]=True;next_policy[-1]=False;next_policy[i_reset]=False
        if np.array_equal(next_policy,policy):
            break
        policy=next_policy
    else:
        raise ArithmeticError('Contextual QVI policy iteration did not converge')

    gen=np.zeros(n)
    gen[1:-1]=below*u[:-2]-(p.r+below+above)*u[1:-1]+above*u[2:]+source[1:-1]
    obstacle=(1-w)*u[li]+w*u[ri]-reset_cost-u
    residual=np.maximum(gen[1:-1],obstacle[1:-1])
    err=float(np.max(np.abs(residual)))
    violation=float(max(np.max(gen[1:-1]),np.max(obstacle[1:-1])))
    tolerance=2e-7*max(1.,float(np.max(np.abs(u))))
    if err > tolerance or violation>tolerance:
        raise ArithmeticError(f'QVI complementarity failure {err=:.4g} {violation=:.4g}')
    crossings=np.where(policy[:-1] & ~policy[1:])[0]
    if len(crossings)!=1 or not (0<crossings[0]<i_reset):
        raise ArithmeticError('More than one or no single lower reset region')
    trigger=float(math.sqrt(v[crossings[0]]*v[crossings[0]+1]))
    return ContextualQVIResult(v,u,policy,reset_target,reset_cost,trigger,
                                iterations,err,violation,gen,obstacle)
