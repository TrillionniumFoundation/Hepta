"""Independent adaptive second-hit checks: quadrature, MC, gradients, rejects."""
from __future__ import annotations
import math
import unittest
import numpy as np
from scipy.integrate import quad
from scipy.special import expit
import torch
try:
    from .adaptive_second_hit import adaptive_second_hit_law
    from .moving_boundary_first_passage import density_reference
except ImportError:
    from adaptive_second_hit import adaptive_second_hit_law
    from moving_boundary_first_passage import density_reference


def t(v,grad=False):
    return torch.tensor(v,dtype=torch.float64,requires_grad=grad)


def case(**overrides):
    pars=dict(x0=t(.55),drift=t(-.18),sigma=t(.58),horizon=t(4.5),
              discount=t(.22),reset_base=t([.39,.85]),
              reset_amplitudes=t([.30,-.22]),mode_bias=t(-.38),
              mode_slope=t(1.8),refractory_base=t(.19),
              refractory_slope=t(.3))
    pars.update(overrides)
    return adaptive_second_hit_law(**pars)


def independent_nested_reference(x0=.55,mu=-.18,sig=.58,T=4.5,lam=.22,
                                 resets=(.39,.85),amps=(.3,-.22),
                                 bias=-.38,slope=1.8,rho=.19,rho_slope=.3):
    """Separate SciPy numerical double-density integration; no CDF call."""
    def integrand(s, discounted):
        if s<=0 or s>=T:return 0.
        f=x0/(sig*math.sqrt(2*math.pi*s**3))*math.exp(-((x0+mu*s)**2)/(2*sig**2*s))
        r=rho*(1+rho_slope*s/T)
        rem=T-s-r
        if rem<=0:return 0.
        prob1=expit(bias+slope*(s/T-.5))
        result=0.
        for z in (0,1):
            distance=resets[z]*(1+amps[z]*math.sin(2*math.pi*s/T))
            val=density_reference(distance,rem,mu,sig,0.,lam if discounted else 0.)[1 if discounted else 0]
            result+=(prob1 if z==1 else 1-prob1)*val
        return f*result*(math.exp(-lam*(s+r)) if discounted else 1.)
    # Integrate the whole horizon; integrand handles the *actual*
    # time-dependent feasibility condition s+rho(s)<T exactly.
    v=quad(lambda s:integrand(s,False),0,T,epsabs=8e-9,epsrel=2e-8,limit=220)[0]
    g=quad(lambda s:integrand(s,True),0,T,epsabs=8e-9,epsrel=2e-8,limit=220)[0]
    return v,g


class TestAdaptiveSecondHit(unittest.TestCase):
    def test_mass_discount_and_refinement(self):
        z=case()
        self.assertAlmostEqual(float(z.probability_zero+z.probability_exactly_one+z.probability_two_or_more),1.,12)
        self.assertLessEqual(float(z.discounted_second),float(z.probability_second))
        self.assertLessEqual(float(z.probability_second),float(z.probability_first))
        self.assertLess(z.quadrature_max_refinement,3e-7)
        self.assertFalse(z.scientific_admission)

    def test_agrees_independent_density_of_two_hits(self):
        v,g=independent_nested_reference()
        z=case()
        self.assertAlmostEqual(float(z.probability_second),v,delta=1.5e-7)
        self.assertAlmostEqual(float(z.discounted_second),g,delta=1.5e-7)

    def test_zero_time_dependence_matches_exact_renewal(self):
        # Stationary reset -> strong Markov hitting convolution collapses to
        # first hit from x0+Rz, shifted by constant refractory.
        z=case(reset_amplitudes=t([0.,0.]),mode_slope=t(0.),
               refractory_slope=t(0.))
        p=expit(-.38);w=(1-p,p)
        f=g=0.
        for q,r in zip(w,(.39,.85)):
            a,b=density_reference(.55+r,4.5-.19,-.18,.58,0.,.22)
            f+=q*a;g+=q*b*math.exp(-.22*.19)
        self.assertAlmostEqual(float(z.probability_second),f,delta=2e-7)
        self.assertAlmostEqual(float(z.discounted_second),g,delta=2e-7)

    def test_different_causal_schedules_change_events(self):
        nonstat=case()
        constant=case(reset_amplitudes=t([0.,0.]),mode_slope=t(0.),
                      refractory_slope=t(0.))
        self.assertGreater(abs(float(nonstat.probability_second-constant.probability_second)),.001)

    def test_all_finite_autograd_matches_signed_fd(self):
        # Every coordinate (including reset probabilities and time-dependent
        # parameters) contributes to a continuous EXPECTATION gradient.
        vals=[.55,-.18,.58,4.5,.22,.39,.85,.30,-.22,-.38,1.8,.19,.3]
        def evaluate(a):
            u=list(a)
            z=case(x0=u[0],drift=u[1],sigma=u[2],horizon=u[3],discount=u[4],
                   reset_base=torch.stack((u[5],u[6])),
                   reset_amplitudes=torch.stack((u[7],u[8])),
                   mode_bias=u[9],mode_slope=u[10],refractory_base=u[11],
                   refractory_slope=u[12])
            return z.probability_second+.67*z.discounted_second+.11*z.probability_first
        vv=t(vals,True)
        outcome=evaluate(vv)
        grad=torch.autograd.grad(outcome,vv)[0]
        self.assertTrue(bool(torch.isfinite(grad).all()))
        for j in range(len(vals)):
            plus=vv.detach().clone();minus=vv.detach().clone();eps=1e-5
            plus[j]+=eps;minus[j]-=eps
            fd=float((evaluate(plus)-evaluate(minus))/(2*eps))
            self.assertAlmostEqual(float(grad[j]),fd,delta=3e-6+3e-5*abs(fd),msg=f'coordinate {j}')

    def test_exact_time_monte_carlo_beyond_time_grid(self):
        # Uses NumPy Wald (exact negative-drift IG hitting) and random mode
        # allocation, not bridge discretization or analytic CDF evaluation.
        rng=np.random.default_rng(271828)
        N=180000
        mu=-.18;sig=.58;T=4.5;lam=.22;x0=.55
        first=rng.wald(x0/abs(mu),(x0/sig)**2,size=N)
        safe=np.minimum(first/T,2.)
        one=expit(-.38+1.8*(safe-.5))
        zs=(rng.random(N)<one).astype(np.int8)
        resets=np.where(zs==0,.39*(1+.30*np.sin(2*math.pi*safe)),
                        .85*(1-.22*np.sin(2*math.pi*safe)))
        rho=.19*(1+.3*safe)
        second=rng.wald(resets/abs(mu),(resets/sig)**2)
        hit=(first+rho+second)<=T
        prob=float(hit.mean())
        exp=float(np.mean(np.where(hit,np.exp(-lam*(first+rho+second)),0.)))
        z=case()
        q=float(z.probability_second)
        g=float(z.discounted_second)
        se=math.sqrt(max(q*(1-q),1e-6)/N)
        se_reward=float(np.std(np.where(hit,np.exp(-lam*(first+rho+second)),0.),ddof=1)/math.sqrt(N))
        self.assertLess(abs(q-prob),5*se+.0005)
        self.assertLess(abs(g-exp),5*se_reward+.0005)

    def test_bounded_randomized_refinement_panels(self):
        # Deterministic, preselected exploratory domain grid; *not* proof
        # of uniform error bounds outside the declared finite panels.
        rng=np.random.default_rng(1337)
        max_err=0.
        for _ in range(125):
            z=case(x0=t(rng.uniform(.2,1.5)),drift=t(rng.uniform(-.35,.35)),
                   sigma=t(rng.uniform(.25,.9)),horizon=t(rng.uniform(1.2,7)),
                   discount=t(rng.uniform(.01,1)),
                   reset_base=t(rng.uniform(.17,1.7,size=2)),
                   reset_amplitudes=t(rng.uniform(-.38,.38,size=2)),
                   mode_bias=t(rng.uniform(-3,3)),mode_slope=t(rng.uniform(-4,4)),
                   refractory_base=t(rng.uniform(.05,.8)),
                   refractory_slope=t(rng.uniform(-.45,.45)))
            self.assertLessEqual(z.quadrature_max_refinement,3e-7)
            max_err=max(max_err,z.quadrature_max_refinement)
        self.assertLess(max_err,1e-7)

    def test_discount_zero_and_impossible_second_hit(self):
        # If refractory alone is longer than horizon, no second hit occurs;
        # the first spike law remains exact and independent of reset state.
        z=case(horizon=t(1.0),refractory_base=t(1.2),
               refractory_slope=t(0.),discount=t(0.))
        self.assertEqual(float(z.probability_second),0.)
        self.assertEqual(float(z.discounted_second),0.)
        self.assertEqual(float(z.discounted_first),float(z.probability_first))

    def test_fail_closed_nonfinite_shapes_and_refinement(self):
        with self.assertRaises(ValueError):case(reset_amplitudes=t([.5,0.]))
        with self.assertRaises(ValueError):case(refractory_slope=t(-.7))
        with self.assertRaises(ValueError):case(x0=t(float('nan')))
        with self.assertRaises(TypeError):case(mode_bias=torch.tensor(0.))
        with self.assertRaises(TypeError):case(reset_base=t([.3,.4,.5]))
        with self.assertRaises(ValueError):case(discount=t(0.,True))
        with self.assertRaises(ValueError):case(coarse_order=96,fine_order=96)
        with self.assertRaises(ArithmeticError):case(coarse_order=24,fine_order=32,tolerance=1e-12)


if __name__=='__main__':unittest.main()
