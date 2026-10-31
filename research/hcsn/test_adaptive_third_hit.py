"""Independent 3-event renewal evidence: constant collapse, MC and gradients."""
from __future__ import annotations
import math
import unittest
import numpy as np
import torch
from scipy.special import expit
try:
    from .adaptive_third_hit import adaptive_third_hit_law
    from .test_adaptive_second_hit import case,t
    from .moving_boundary_first_passage import density_reference
except ImportError:
    from adaptive_third_hit import adaptive_third_hit_law
    from test_adaptive_second_hit import case,t
    from moving_boundary_first_passage import density_reference


def third(**overrides):
    p=dict(x0=t(.55),drift=t(-.18),sigma=t(.58),horizon=t(4.5),discount=t(.22),
           reset_base=t([.39,.85]),reset_amplitudes=t([.30,-.22]),
           mode_bias=t(-.38),mode_slope=t(1.8),refractory_base=t(.19),
           refractory_slope=t(.3))
    p.update(overrides)
    return adaptive_third_hit_law(**p)


class TestAdaptiveThirdHit(unittest.TestCase):
    def test_monotonic_third_and_double_count_lower_bound(self):
        z=third()
        self.assertGreater(float(z.third_probability),0.)
        self.assertLess(float(z.third_probability),float(z.second_probability))
        self.assertLess(float(z.discounted_third),float(z.third_probability))
        self.assertAlmostEqual(float(z.third_count_lower_bound),float(z.first_probability+z.second_probability+z.third_probability),12)
        self.assertFalse(z.scientific_admission)
        self.assertLess(z.numerical_refinement,2e-6)

    def test_stationary_independent_third_hit_density(self):
        z=third(reset_amplitudes=t([0.,0.]),mode_slope=t(0.),refractory_slope=t(0.))
        pi=(1-expit(-.38),expit(-.38))
        f3=g3=0.
        for i in range(2):
            for j in range(2):
                distance=.55+(.39,.85)[i]+(.39,.85)[j]
                f,g=density_reference(distance,4.5-2*.19,-.18,.58,0.,.22)
                f3+=pi[i]*pi[j]*f
                g3+=pi[i]*pi[j]*g*math.exp(-.22*2*.19)
        self.assertAlmostEqual(float(z.third_probability),f3,delta=2e-7)
        self.assertAlmostEqual(float(z.discounted_third),g3,delta=2e-7)

    def test_nonstationary_independent_exact_wald_monte_carlo(self):
        N=180000;mu=-.18;sig=.58;T=4.5;lam=.22
        rng=np.random.default_rng(314159)
        dt1=rng.wald(.55/abs(mu),(.55/sig)**2,size=N)
        x1=np.minimum(dt1/T,1.)
        z1=(rng.random(N)<expit(-.38+1.8*(x1-.5))).astype(int)
        R1=np.where(z1==0,.39*(1+.3*np.sin(2*math.pi*x1)),
                               .85*(1-.22*np.sin(2*math.pi*x1)))
        dt2=rng.wald(R1/abs(mu),(R1/sig)**2)
        s2=dt1+.19*(1+.3*x1)+dt2
        x2=np.minimum(s2/T,1.)
        z2=(rng.random(N)<expit(-.38+1.8*(x2-.5))).astype(int)
        R2=np.where(z2==0,.39*(1+.3*np.sin(2*math.pi*x2)),
                               .85*(1-.22*np.sin(2*math.pi*x2)))
        dt3=rng.wald(R2/abs(mu),(R2/sig)**2)
        t3=s2+.19*(1+.3*x2)+dt3
        mask=t3<=T
        empirical=float(mask.mean())
        r=np.where(mask,np.exp(-lam*t3),0.)
        reward=float(r.mean())
        z=third()
        p=float(z.third_probability);g=float(z.discounted_third)
        se=math.sqrt(max(p*(1-p),1e-7)/N)
        se_r=float(np.std(r,ddof=1)/math.sqrt(N))
        self.assertLess(abs(p-empirical),5*se+.0005)
        self.assertLess(abs(g-reward),5*se_r+.0005)

    def test_signed_gradients_all_13_parameters(self):
        vv=t([.55,-.18,.58,4.5,.22,.39,.85,.30,-.22,-.38,1.8,.19,.3],True)
        def objective(a):
            p=list(a)
            z=third(x0=p[0],drift=p[1],sigma=p[2],horizon=p[3],discount=p[4],
                    reset_base=torch.stack((p[5],p[6])),
                    reset_amplitudes=torch.stack((p[7],p[8])),
                    mode_bias=p[9],mode_slope=p[10],refractory_base=p[11],
                    refractory_slope=p[12])
            return z.third_probability+.29*z.discounted_third
        grad=torch.autograd.grad(objective(vv),vv)[0]
        self.assertTrue(bool(torch.isfinite(grad).all()))
        for i in range(len(vv)):
            a=vv.detach().clone();b=vv.detach().clone();eps=1e-5
            a[i]+=eps;b[i]-=eps
            finite=float((objective(a)-objective(b))/(2*eps))
            self.assertAlmostEqual(float(grad[i]),finite,delta=3e-6+4e-5*abs(finite),msg=f'coordinate {i}')

    def test_randomized_bounded_refinement_and_positive_drift(self):
        rng=np.random.default_rng(1338)
        largest=0.
        for _ in range(90):
            z=third(x0=t(rng.uniform(.25,1.4)),drift=t(rng.uniform(-.35,.35)),
                    sigma=t(rng.uniform(.28,.9)),horizon=t(rng.uniform(1.5,7)),
                    discount=t(rng.uniform(.01,1)),
                    reset_base=t(rng.uniform(.18,1.6,size=2)),
                    reset_amplitudes=t(rng.uniform(-.35,.35,size=2)),
                    mode_bias=t(rng.uniform(-3,3)),mode_slope=t(rng.uniform(-4,4)),
                    refractory_base=t(rng.uniform(.05,.55)),
                    refractory_slope=t(rng.uniform(-.45,.45)))
            self.assertLess(z.numerical_refinement,2e-6)
            largest=max(largest,z.numerical_refinement)
        self.assertLess(largest,1e-6)

    def test_zero_three_events_and_fail_closed(self):
        z=third(horizon=t(1.),refractory_base=t(1.2),refractory_slope=t(0.))
        self.assertEqual(float(z.third_probability),0.)
        with self.assertRaises(ValueError):third(coarse_order=128,fine_order=48)
        with self.assertRaises(ValueError):third(reset_base=t([0.01,.85]))
        with self.assertRaises(ArithmeticError):third(coarse_order=16,fine_order=20,tolerance=1e-12)


if __name__=='__main__':unittest.main()
