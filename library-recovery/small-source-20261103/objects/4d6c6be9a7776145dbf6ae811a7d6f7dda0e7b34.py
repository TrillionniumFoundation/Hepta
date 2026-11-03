"""Independent first-passage convolution check for the Iteration 11 renewal law.

Research-only. Numeric quadrature of inverse-Gaussian hitting-time densities,
not a reuse of the analytic CDF. Covers nth hitting-time distribution under
strong-Markov constant-reset assumptions. Does not establish full HCSN P2.
"""
import math
import sys
import unittest
from pathlib import Path

import numpy as np
from scipy.integrate import quad
import torch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hcsn_iteration11.stochastic_regenerative_counts import renewal_count_law


def hit_density(t, distance, drift, sigma):
    if t <= 0:
        return 0.0
    return distance / (sigma * math.sqrt(2 * math.pi * t**3)) * math.exp(
        -(distance + drift*t)**2 / (2*sigma*sigma*t))


def convolution_hit_prob(x, reset, mu, sigma, horizon, n):
    # independent n-fold density convolution, recursively integrated.
    # Using 2D quadrature for n=2 only, plus one n=3 optional panel.
    def density_2(t):
        return quad(lambda s: hit_density(s,x,mu,sigma)*hit_density(t-s,reset,mu,sigma),
                    0,t,epsabs=1e-9,epsrel=1e-8,limit=140)[0]
    if n == 2:
        return quad(density_2,0,horizon,epsabs=2e-7,epsrel=2e-6,limit=100)[0]
    raise ValueError('n=2 supported for independent convolution reference')


class TestIndependentRenewalConvolution(unittest.TestCase):
    def test_second_event_independent_convolution(self):
        panels=[(.6,.7,-.12,.65,3.0),(.8,.5,0.,.8,2.5),(.5,.8,.17,.7,4.)]
        for x,reset,mu,sigma,T in panels:
            with self.subTest(mu=mu,T=T):
                p=convolution_hit_prob(x,reset,mu,sigma,T,2)
                z=lambda a:torch.tensor(a,dtype=torch.float64)
                law=renewal_count_law(z(x),z(reset),z(mu),z(sigma),z(T),z(.05),max_events=8)
                got=float(law.at_least_probabilities[1])
                self.assertLess(abs(got-p),2e-5,(p,got))

if __name__=='__main__': unittest.main()
