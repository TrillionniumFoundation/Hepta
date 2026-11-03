"""Two-regime, finite-state regenerative QVI reference.

The discrete grid is a *numerical surrogate* for a continuous-time switching
problem, not a reproduction of the He-Xiong debt/rollover equilibrium.
Solves V=max(r dt + exp(-rho dt) P V, R V - switching_cost).
Two independently implemented algorithms: policy iteration (linear solve) and
Bellman iteration.  An impulse is instantaneous and incurs strictly positive cost.
"""
from dataclasses import dataclass
import numpy as np

@dataclass(frozen=True)
class Model:
    n: int = 25
    dt: float = 0.04
    rho: float = 0.15
    drift: float = 0.01
    sigma: float = 0.18
    reset_cost: float = 0.18

    def __post_init__(self):
        if self.n < 5 or not (0 < self.dt <= 1) or self.rho <= 0 or self.sigma < 0 or self.reset_cost <= 0:
            raise ValueError('invalid physical/switching domain')
        # For a stochastic explicit Markov approximation, CFL must hold.
        h=1/(self.n-1)
        if self.dt*(self.sigma**2/h**2+abs(self.drift)/h) > 1:
            raise ValueError('unstable Markov grid / CFL violation')

def system(m):
    m.__post_init__()
    n=m.n; h=1/(n-1)
    x=np.linspace(0,1,n)
    p_up=m.dt*(m.sigma**2/(2*h*h)+max(m.drift,0)/h)
    p_down=m.dt*(m.sigma**2/(2*h*h)+max(-m.drift,0)/h)
    P=np.zeros((n,n))
    for i in range(n):
        P[i,i]=1-p_up-p_down
        P[i,min(i+1,n-1)]+=p_up
        P[i,max(i-1,0)]+=p_down
    assert np.all(P>=-1e-14) and np.max(np.abs(P.sum(axis=1)-1))<1e-12
    T=np.zeros((2*n,2*n));T[:n,:n]=P;T[n:,n:]=P
    # Two distinct continuation rewards and coupled reset actions.
    r=np.r_[0.12+np.exp(-((x-0.22)/0.17)**2), 0.12+np.exp(-((x-0.78)/0.17)**2)]
    targets=np.r_[np.full(n,n+int(round(0.78*(n-1)))),np.full(n,int(round(0.22*(n-1))))]
    return T,r,targets

def residual(v,m,T,r,target):
    gamma=np.exp(-m.rho*m.dt)
    cont=m.dt*r+gamma*T@v
    impulse=v[target]-m.reset_cost
    return float(np.max(np.abs(v-np.maximum(cont,impulse))))

def policy_iteration(m, max_iter=200):
    T,r,target=system(m); count=len(r); gamma=np.exp(-m.rho*m.dt)
    policy=np.zeros(count,dtype=bool)
    v=np.zeros(count)
    for it in range(max_iter):
        A=np.eye(count);b=np.zeros(count)
        for i in range(count):
            if policy[i]: A[i,target[i]]-=1; b[i]=-m.reset_cost
            else: A[i,:]-=gamma*T[i,:];b[i]=m.dt*r[i]
        v=np.linalg.solve(A,b)
        cont=m.dt*r+gamma*T@v
        impulse=v[target]-m.reset_cost
        new=impulse>cont+1e-10
        if np.array_equal(new,policy):
            return v,policy,it+1,residual(v,m,T,r,target)
        policy=new
    raise RuntimeError('policy iteration did not converge')

def bellman_iteration(m,tol=1e-10,max_iter=50000):
    T,r,target=system(m); gamma=np.exp(-m.rho*m.dt)
    v=np.zeros(len(r))
    for it in range(max_iter):
        # Jacobi iteration, algorithmically independent of policy iteration.
        w=np.maximum(m.dt*r+gamma*T@v,v[target]-m.reset_cost)
        if np.max(np.abs(w-v))<tol:
            return w,it+1,residual(w,m,T,r,target)
        v=w
    raise RuntimeError('Bellman iteration did not converge')

def check():
    records=[]
    for cost in [0.08,0.18,0.35,1.0,100.0]:
        m=Model(reset_cost=cost)
        vp,policy,pit,pr=policy_iteration(m)
        vb,bit,br=bellman_iteration(m)
        diff=float(np.max(np.abs(vp-vb)))
        assert diff<1e-7 and pr<1e-8 and br<1e-8,(cost,diff,pr,br)
        records.append((cost,int(policy.sum()),pit,bit,diff,pr,br,float(vp.mean())))
    # Removing an available intervention (huge cost) cannot improve value.
    assert all(records[i][-1]>=records[i+1][-1]-1e-8 for i in range(len(records)-1))
    # First regime and second regime must both have reachable impulses at low cost.
    m=Model(reset_cost=0.08); _,policy,_,_=policy_iteration(m)
    assert policy[:m.n].any() and policy[m.n:].any()
    for bad in [dict(rho=0),dict(reset_cost=0),dict(n=2),dict(dt=1,sigma=1)]:
        try: Model(**bad)
        except ValueError: pass
        else: raise AssertionError(('validation failure',bad))
    return records

if __name__=='__main__':
    for cost,sw,pit,bit,diff,pr,br,mean in check():
        print(f'cost={cost:.2f} impulse_states={sw:2d} policy_iter={pit:2d} bellman_iter={bit:4d} max_difference={diff:.3g} policy_res={pr:.3g} bellman_res={br:.3g} mean_value={mean:.5f}')
    print('PASS: 2-regime regenerative QVI, independent policy/Bellman agreement')
