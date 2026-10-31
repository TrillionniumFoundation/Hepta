"""Independent references for stationary two-state Markov regenerative barrier model."""
from __future__ import annotations
import itertools
import math
import unittest
import numpy as np
import torch
try:
    from .markov_reset_renewal import markov_reset_count_law
    from .stochastic_regenerative_counts import renewal_count_law
    from .moving_boundary_first_passage import density_reference
except ImportError:
    from markov_reset_renewal import markov_reset_count_law
    from stochastic_regenerative_counts import renewal_count_law
    from moving_boundary_first_passage import density_reference


def t(x, grad=False):
    return torch.tensor(x,dtype=torch.float64,requires_grad=grad)


def call(**overrides):
    pars=dict(x0=t(.53),reset_margins=t([.34,.89]),initial_mode=t([.37,.63]),
              transition=t([[.81,.19],[.26,.74]]),drift=t(-.17),sigma=t(.54),
              horizon=t(4.6),discount=t(.31),refractory=t(.12),max_events=7)
    pars.update(overrides)
    return markov_reset_count_law(**pars)


def enumerated_reference(k,x0,resets,pi,P,drift,sigma,T,discount,rho):
    """2^k independent exhaustive mode-path enumeration + density quadrature."""
    if k==0:
        f,g=density_reference(x0,T,drift,sigma,0.,discount)
        return f,g
    remaining=T-k*rho
    if remaining<=0:
        return 0.,0.
    F=G=0.
    for seq in itertools.product((0,1),repeat=k):
        w=pi[seq[0]]
        for a,b in zip(seq,seq[1:]):
            w*=P[a][b]
        x=x0+sum(resets[j] for j in seq)
        f,g=density_reference(x,remaining,drift,sigma,0.,discount)
        F+=w*f
        G+=w*g*math.exp(-discount*k*rho)
    return F,G


class TestMarkovRenewal(unittest.TestCase):
    def test_mass_censoring_and_unconditional_bounds(self):
        z=call(max_events=8)
        self.assertEqual(tuple(z.exact_count_probabilities.shape),(9,))
        self.assertEqual(tuple(z.at_least_probabilities.shape),(9,))
        self.assertAlmostEqual(float(z.exact_count_probabilities.sum()+z.overflow_probability),1.,12)
        self.assertGreater(float(z.overflow_probability),0.)
        self.assertTrue(bool((z.exact_count_probabilities>=-1e-13).all()))
        self.assertTrue(bool((z.at_least_probabilities[1:]<=z.at_least_probabilities[:-1]+1e-12).all()))
        self.assertLessEqual(float(z.discounted_event_reward_lower_bound),float(z.expected_count_lower_bound)+1e-12)
        self.assertFalse(z.scientific_admission)

    def test_exact_independent_path_enumeration_and_density(self):
        z=call(max_events=6)
        pars=dict(x0=.53,resets=(.34,.89),pi=(.37,.63),
                  P=((.81,.19),(.26,.74)),drift=-.17,sigma=.54,
                  T=4.6,discount=.31,rho=.12)
        for k in range(7):
            f,g=enumerated_reference(k,**pars)
            self.assertAlmostEqual(float(z.at_least_probabilities[k]),f,places=9)
            if k<6:
                # Reward per n-th event must be recovered by difference of prefix sums.
                p=call(max_events=k+1).discounted_event_reward_lower_bound
                q=t(0.) if k==0 else call(max_events=k).discounted_event_reward_lower_bound
                self.assertAlmostEqual(float(p-q),g,places=9)

    def test_equivalence_fixed_reset_when_margins_identical(self):
        z=call(reset_margins=t([.57,.57]),refractory=t(0.),max_events=10)
        base=renewal_count_law(t(.53),t(.57),t(-.17),t(.54),t(4.6),t(.31),max_events=10)
        self.assertTrue(torch.allclose(z.at_least_probabilities,base.at_least_probabilities,atol=2e-14,rtol=0))
        self.assertAlmostEqual(float(z.discounted_event_reward_lower_bound),
                               float(base.discounted_event_reward_lower_bound),places=12)

    def test_deterministic_alternation(self):
        z=call(initial_mode=t([1.,0.]),transition=t([[0.,1.],[1.,0.]]),max_events=8)
        for k in range(9):
            x=.53+math.ceil(k/2)*.34+math.floor(k/2)*.89
            remaining=4.6-.12*k
            f,g=density_reference(x,remaining,-.17,.54,0.,.31)
            self.assertAlmostEqual(float(z.at_least_probabilities[k]),f,places=10)

    def test_markov_correlations_affect_third_and_later_events(self):
        params=dict(initial_mode=t([.5,.5]),reset_margins=t([.12,1.4]),
                    max_events=5,drift=t(-.1),sigma=t(.45),horizon=t(5.))
        stay=call(**params,transition=t([[.99,.01],[.01,.99]]))
        flip=call(**params,transition=t([[.01,.99],[.99,.01]]))
        self.assertAlmostEqual(float(stay.at_least_probabilities[1]),float(flip.at_least_probabilities[1]),12)
        self.assertGreater(abs(float(stay.at_least_probabilities[2]-flip.at_least_probabilities[2])),.005)

    def test_refractory_disallows_early_second_event(self):
        z=call(refractory=t(3.2),horizon=t(2.6),max_events=8)
        self.assertGreater(float(z.at_least_probabilities[0]),0.)
        self.assertTrue(bool((z.at_least_probabilities[1:]==0).all()))
        self.assertAlmostEqual(float(z.overflow_probability),0.,12)

    def test_positive_drift_defective_asymptote(self):
        # If drift>0, eventual hitting is defective: exp(-2 mu x/sigma^2).
        z=call(drift=t(.27),sigma=t(.4),horizon=t(100.),
               refractory=t(0.),max_events=3)
        x=.53; mu=.27; sig=.4; R=(.34,.89); pi=(.37,.63)
        eventual1=math.exp(-2*mu*x/sig**2)
        eventual2=sum(pi[j]*math.exp(-2*mu*(x+R[j])/sig**2) for j in (0,1))
        self.assertLess(abs(float(z.at_least_probabilities[0])-eventual1),1e-5)
        self.assertLess(abs(float(z.at_least_probabilities[1])-eventual2),1e-5)

    def test_gradient_matches_independent_finite_differences(self):
        def objective(v, compute_grad=False):
            # Domain-valid differentiable parameterization, no row-normalization shortcuts.
            x,R0,R1,mu,sig,T,lam,rho,p_init,qa,qb=v
            pi=torch.stack((1-torch.sigmoid(p_init),torch.sigmoid(p_init)))
            a=torch.sigmoid(qa); b=torch.sigmoid(qb)
            P=torch.stack((torch.stack((1-a,a)),torch.stack((b,1-b))))
            z=call(x0=x,reset_margins=torch.stack((R0,R1)),initial_mode=pi,
                   transition=P,drift=mu,sigma=sig,horizon=T,discount=lam,
                   refractory=rho,max_events=6)
            return z.expected_count_lower_bound + .37*z.discounted_event_reward_lower_bound + .13*z.exact_count_probabilities[2]
        v=t([.53,.34,.89,-.17,.54,4.6,.31,.12,.21,-.43,.56],grad=True)
        y=objective(v)
        grad=torch.autograd.grad(y,v)[0]
        self.assertTrue(bool(torch.isfinite(grad).all()))
        with torch.no_grad():
            for j in range(len(v)):
                plus=v.detach().clone(); minus=v.detach().clone()
                plus[j]+=1e-5; minus[j]-=1e-5
                fd=float((objective(plus)-objective(minus))/(2e-5))
                self.assertAlmostEqual(float(grad[j]),fd,delta=2e-6+2e-5*abs(fd),msg=f'gradient coordinate {j}')

    def test_fail_closed_and_tail_budget(self):
        with self.assertRaises(ArithmeticError):call(maximum_censored_tail=1e-12)
        with self.assertRaises(ValueError):call(initial_mode=t([.5,.6]))
        with self.assertRaises(ValueError):call(transition=t([[.8,.2],[.2,.7]]))
        with self.assertRaises(ValueError):call(reset_margins=t([0.,.3]))
        with self.assertRaises(ValueError):call(refractory=t(-.01))
        with self.assertRaises(ValueError):call(discount=t(0.,grad=True))
        with self.assertRaises(ValueError):call(x0=t(float('nan')))
        with self.assertRaises(ValueError):call(max_events=True)
        with self.assertRaises(TypeError):call(initial_mode=torch.tensor([.3,.7],dtype=torch.float32))

    def test_strict_refractory_tail_conservation_grid(self):
        for mu in (-.37,0.,.22):
            for r in (0.,.3,1.1):
                for K in (1,3,7,12):
                    z=call(drift=t(mu),refractory=t(r),max_events=K)
                    self.assertAlmostEqual(float(z.exact_count_probabilities.sum()+z.overflow_probability),1.,places=11)

    def test_independent_exact_time_monte_carlo(self):
        # Independent waiting-time sampler: NumPy Wald is NOT the CDF kernel.
        # Changes in reset mode are history-dependent, not IID.
        rng=np.random.default_rng(120269)
        N=80000
        x0=.53; resets=np.array([.34,.89]); pi=np.array([.37,.63]);
        P=np.array([[.81,.19],[.26,.74]])
        mu=-.17; sigma=.54; T=4.6; rho=.12; disc=.31; K=6
        cumul=np.zeros(N); counts=np.zeros(N,dtype=np.int32)
        reward=np.zeros(N)
        modes=np.zeros(N,dtype=np.int32)
        distances=np.full(N,x0)
        for event in range(K+2):
            # Negative drift -> proper IG first-hit time, no Euler timestep bias.
            dt=rng.wald(distances/abs(mu),(distances/sigma)**2)
            cumul+=dt+(rho if event>0 else 0.)
            hits=cumul<=T
            counts+=hits
            if event<K:
                reward+=hits*np.exp(-disc*cumul)
            if event==0:
                modes=(rng.random(N)>=pi[0]).astype(np.int32)
            else:
                modes=(rng.random(N)>=P[modes,0]).astype(np.int32)
            distances=resets[modes]
        z=call(max_events=K)
        # z.count n<=K ; CDF overflow means count>K, not >=K.
        for n in range(1,K+2):
            emp=np.mean(counts>=n)
            analytic=float(z.at_least_probabilities[n-1])
            se=math.sqrt(max(analytic*(1-analytic),1e-8)/N)
            self.assertLess(abs(emp-analytic),5*se+.001,msg=f'event {n}')
        emp_reward=np.mean(reward)
        analytic_reward=float(z.discounted_event_reward_lower_bound)
        se_reward=float(np.std(reward,ddof=1)/math.sqrt(N))
        self.assertLess(abs(emp_reward-analytic_reward),5*se_reward+.002)


if __name__=='__main__':unittest.main()
