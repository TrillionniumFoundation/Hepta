import math
import platform
import numpy as np
import scipy
from scipy.integrate import quad
from scipy.special import ndtr, log_ndtr
from scipy.sparse import diags
from scipy.sparse.linalg import splu
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def channels(z, gamma):
    z = np.asarray(z, dtype=float)
    if gamma <= 0 or np.any(z < 1):
        raise ValueError("Require gamma>0, z>=1.")
    logz = np.log(z)
    # Stable enough near z=1; use a Taylor branch for the cancelling linear terms.
    C = np.expm1(logz) + np.expm1(-gamma*logz)/gamma
    small = np.abs(logz) < 1e-4
    series = ((1+gamma)*logz**2/2
              +(1-gamma**2)*logz**3/6
              +(1+gamma**3)*logz**4/24
              +(1-gamma**4)*logz**5/120)
    return np.where(small, series, C), np.exp(-gamma*logz)

def risk(x, T, nu, sigma):
    x = np.asarray(x, dtype=float)
    if T <= 0 or sigma <= 0 or np.any(x < 0):
        raise ValueError("Require x>=0, T>0, sigma>0.")
    scale = sigma*np.sqrt(T)
    log1 = log_ndtr((-x-nu*T)/scale)
    log2 = -2*nu*x/sigma**2 + log_ndtr((-x+nu*T)/scale)
    return np.exp(np.minimum(np.logaddexp(log1, log2), 0.0))

def risk_dx(x, T, nu, sigma):
    # Moderate-domain analytic derivative, used only on the stated audit grid.
    scale = sigma*np.sqrt(T)
    a, b = (-x-nu*T)/scale, (-x+nu*T)/scale
    phi = lambda z: np.exp(-z*z/2)/np.sqrt(2*np.pi)
    return (-phi(a)/scale + np.exp(-2*nu*x/sigma**2) *
            (-2*nu*ndtr(b)/sigma**2-phi(b)/scale))

def density(x, t, nu, sigma):
    if x <= 0 or np.any(np.asarray(t) <= 0) or sigma <= 0:
        raise ValueError("Require x,t,sigma>0.")
    return x/(sigma*np.sqrt(2*np.pi*t**3))*np.exp(
        -(x+nu*t)**2/(2*sigma**2*t))

def killed(z, x, t, nu, sigma):
    z = np.asarray(z)
    if np.any(z < 0) or x <= 0 or t <= 0 or sigma <= 0:
        raise ValueError("Require z>=0 and x,t,sigma>0.")
    return (np.exp(-(z-x-nu*t)**2/(2*sigma**2*t))
            /(sigma*np.sqrt(2*np.pi*t))
            *(-np.expm1(-2*x*z/(sigma**2*t))))

def pde_risk(x, T, nu, sigma, dx, steps, xmax=8.0):
    # Independent finite-difference backward PDE:
    # P_T = nu P_x + D P_xx, P(0,T)=1, P(xmax,T)=0, P(x,0)=0.
    # Finite xmax is an approximation; it is far beyond diffusion support here.
    N = round(xmax/dx)
    dx = xmax/N
    n, D = N-1, sigma*sigma/2
    lower, upper = D/dx**2-nu/(2*dx), D/dx**2+nu/(2*dx)
    M = diags([np.full(n-1,lower), np.full(n,-2*D/dx**2),
               np.full(n-1,upper)], [-1,0,1],format="csc")
    I = diags([np.ones(n)],[0],format="csc")
    dt = T/steps
    force = np.zeros(n)
    force[0] = lower
    lhs = splu(I-dt*M/2)
    v = np.zeros(n)
    # Two backward Euler half steps replace the first CN step (Rannacher).
    for _ in range(2):
        v = lhs.solve(v+dt*force/2)
    rhs = I+dt*M/2
    for _ in range(steps-1):
        v = lhs.solve(rhs@v+dt*force)
    return float(np.interp(x,np.linspace(0,xmax,N+1),np.r_[1,v,0]))

print({"python":platform.python_version(), "numpy":np.__version__,
       "scipy":scipy.__version__, "matplotlib":matplotlib.__version__})
