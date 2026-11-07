"""Independent numerical convolution validation of stationary regenerative spike counts.

Research only: this verifies the second first-passage event under constant
coefficients and reset, not the endogenous HX free-boundary QVI or trained SNN.
"""
import math
import unittest
from scipy.integrate import quad
import torch
from research.hcsn.stochastic_regenerative_counts import renewal_count_law

def density(t, x, mu, sigma):
    if t <= 0: return 0.0
    return x/(sigma*math.sqrt(2*math.pi*t**3))*math.exp(-(x+mu*t)**2/(2*sigma*sigma*t))

def two_hit_integral(x, reset, mu, sigma, horizon):
    def f(t):
        return quad(lambda s:density(s,x,mu,sigma)*density(t-s,reset,mu,sigma),
                    0,t,epsabs=1e-9,epsrel=1e-8,limit=140)[0]
    return quad(f,0,horizon,epsabs=2e-7,epsrel=2e-6,limit=100)[0]

class TestIndependentRenewalConvolution(unittest.TestCase):
    def test_n2_independent_quadrature(self):
        for x,reset,mu,sigma,T in [(.6,.7,-.12,.65,3.),(.8,.5,0.,.8,2.5),(.5,.8,.17,.7,4.)]:
            with self.subTest(mu=mu,T=T):
                z=lambda a:torch.tensor(a,dtype=torch.float64)
                expected=two_hit_integral(x,reset,mu,sigma,T)
                got=float(renewal_count_law(z(x),z(reset),z(mu),z(sigma),z(T),z(.05),max_events=8).at_least_probabilities[1])
                self.assertLess(abs(got-expected),2e-5)

if __name__=="__main__": unittest.main()
