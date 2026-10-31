"""Independent tests of autonomous continuous-time, multiple-reset law."""
import math
import unittest
import numpy as np
import torch
try:
    from .stochastic_regenerative_counts import renewal_count_law
    from .moving_boundary_first_passage import density_reference
except ImportError:
    from stochastic_regenerative_counts import renewal_count_law
    from moving_boundary_first_passage import density_reference


def t(v,grad=False):
    return torch.tensor(v,dtype=torch.float64,requires_grad=grad)


def solve(x=.7,r=.45,mu=-.08,sigma=.4,T=4.,lam=.12,K=12,**kw):
    return renewal_count_law(t(x),t(r),t(mu),t(sigma),t(T),t(lam),max_events=K,**kw)


def independent_mc(x,r,mu,sigma,T,lam,n,seed,max_events=8):
    """Independent exact-time inverse-Gaussian/Levy renewal *simulation*.

    Simulates actual n independent paths through every reset. Does NOT evaluate
    the analytic hitting CDF, renewal sum, or call implementation under test.
    This is a stochastic check, not a certified confidence statement.
    """
    rng=np.random.default_rng(seed)
    clock=np.zeros(n,dtype=np.float64)
    alive=np.ones(n,dtype=bool)
    count=np.zeros(n,dtype=np.int32)
    discount_rewards=np.zeros(n,dtype=np.float64)
    for k in range(max_events+1):
        idx=np.flatnonzero(alive)
        if len(idx)==0: break
        a=x if k==0 else r
        if abs(mu)<1.e-14:
            z=rng.standard_normal(len(idx))
            dt=np.divide((a/sigma)**2,z*z,
                          out=np.full(len(idx),np.inf),where=z!=0)
        else:
            dt=rng.wald(a/abs(mu),(a/sigma)**2,size=len(idx))
            if mu>0:
                dt[rng.random(len(idx))>math.exp(-2*mu*a/sigma**2)]=np.inf
        clock[idx]+=dt
        hit=clock[idx]<=T
        count[idx[hit]]+=1
        if k<max_events:
            discount_rewards[idx[hit]]+=np.exp(-lam*clock[idx[hit]])
        alive[idx[~hit]]=False
    return count,discount_rewards


class StochasticRenewalTests(unittest.TestCase):
    def test_probability_partition_and_censor_is_explicit(self):
        for mu in (-.32,0.,.22):
            for T in (.3,1.,5.,18.):
                ans=solve(mu=mu,T=T,K=20)
                p=ans.exact_count_probabilities.detach().numpy()
                self.assertEqual(len(p),21)
                self.assertGreaterEqual(min(p),-1e-14)
                self.assertAlmostEqual(p.sum()+float(ans.overflow_probability),1.,places=12)
                self.assertTrue((np.diff(ans.at_least_probabilities.detach().numpy())<=1e-14).all())
                self.assertLessEqual(float(ans.discounted_event_reward_lower_bound),
                                     float(ans.expected_count_lower_bound)+1e-12)
                self.assertFalse(ans.scientific_admission)

    def test_nth_hit_probability_matches_independent_density_integrals(self):
        for mu in (-.23,.0,.14):
            ans=solve(x=.52,r=.37,mu=mu,sigma=.32,T=2.6,lam=.18,K=5)
            for n in (1,2,4):
                distance=.52+(n-1)*.37
                f,g=density_reference(distance,2.6,mu,.32,0.,.18)
                self.assertLess(abs(float(ans.at_least_probabilities[n-1])-f),2.e-10)
                # Recover G_n from the cumulative discounted reward differences
                a=solve(x=.52,r=.37,mu=mu,sigma=.32,T=2.6,lam=.18,K=n)
                b=solve(x=.52,r=.37,mu=mu,sigma=.32,T=2.6,lam=.18,K=n-1) if n>1 else None
                reward=float(a.discounted_event_reward_lower_bound)-(float(b.discounted_event_reward_lower_bound) if b else 0.)
                self.assertLess(abs(reward-g),2.e-10)

    def test_exact_multireset_count_and_discount_vs_independent_mc(self):
        for mu,seed in [(-.25,202601),(0.,202602),(.18,202603)]:
            x=.52;r=.39;sig=.44;horizon=4.;lam=.12;K=8;n=120000
            ans=solve(x=x,r=r,mu=mu,sigma=sig,T=horizon,lam=lam,K=K)
            counts,rewards=independent_mc(x,r,mu,sig,horizon,lam,n,seed,K)
            for k in (0,1,2,3,4):
                observed=np.mean(counts==k)
                predicted=float(ans.exact_count_probabilities[k])
                se=math.sqrt(max(predicted*(1-predicted),1.e-8)/n)
                self.assertLess(abs(observed-predicted),6*se+.001)
            observed_overflow=np.mean(counts>K)
            predicted_overflow=float(ans.overflow_probability)
            se=math.sqrt(max(predicted_overflow*(1-predicted_overflow),1.e-8)/n)
            self.assertLess(abs(observed_overflow-predicted_overflow),6*se+.001)
            # MC counted only first K discounts, exactly matching lower bound.
            predicted_reward=float(ans.discounted_event_reward_lower_bound)
            sd=np.std(rewards,ddof=1)/math.sqrt(n)
            self.assertLess(abs(rewards.mean()-predicted_reward),6*sd+.002)

    def test_differentiable_expected_count_and_reward(self):
        scalars=[.65,.42,-.08,.33,3.2,.17]
        args=[t(v,True) for v in scalars]
        ans=renewal_count_law(*args,max_events=9)
        score=ans.expected_count_lower_bound+.7*ans.discounted_event_reward_lower_bound
        grads=torch.autograd.grad(score,args)
        for i in range(len(args)):
            hi=list(scalars);lo=list(scalars)
            eps=1.e-5
            hi[i]+=eps;lo[i]-=eps
            def f(vals):
                q=renewal_count_law(*(t(v) for v in vals),max_events=9)
                return float(q.expected_count_lower_bound+.7*q.discounted_event_reward_lower_bound)
            finite=(f(hi)-f(lo))/(2*eps)
            self.assertLess(abs(float(grads[i])-finite),3e-6,(i,float(grads[i]),finite))

    def test_more_time_increases_event_probability_and_rewards(self):
        for mu in (-.19,.0,.11):
            a=solve(mu=mu,T=.5)
            b=solve(mu=mu,T=4.)
            self.assertGreaterEqual(float(b.expected_count_lower_bound),float(a.expected_count_lower_bound))
            self.assertGreaterEqual(float(b.discounted_event_reward_lower_bound),float(a.discounted_event_reward_lower_bound))

    def test_refuse_too_many_resets_as_censored_not_certified(self):
        q=solve(x=.2,r=.1,mu=-.3,sigma=.4,T=12.,K=2)
        self.assertGreater(float(q.overflow_probability),.2)
        with self.assertRaises(ArithmeticError):
            solve(x=.2,r=.1,mu=-.3,sigma=.4,T=12.,K=2,maximum_censored_tail=.001)
        accepted=solve(x=.2,r=.1,mu=-.3,sigma=.4,T=12.,K=120,maximum_censored_tail=1.e-4)
        self.assertLess(float(accepted.overflow_probability),1.e-4)

    def test_positive_drift_defective_tail_and_no_discount_identity(self):
        mu=.22;x=.48;r=.44;sig=.38
        ans=solve(x=x,r=r,mu=mu,sigma=sig,T=85.,K=45,lam=0.)
        ever_first=math.exp(-2*mu*x/sig**2)
        ever_repeat=math.exp(-2*mu*r/sig**2)
        eventual_expected=ever_first/(1-ever_repeat)
        self.assertLess(abs(float(ans.expected_count_lower_bound)-eventual_expected),2.e-6)
        self.assertLess(abs(float(ans.discounted_event_reward_lower_bound)-float(ans.expected_count_lower_bound)),1e-13)
        with self.assertRaises(ValueError):
            renewal_count_law(t(.48),t(.44),t(.22),t(.38),t(85.),t(0.,True),max_events=45)

    def test_frozen_randomized_100_domain_panels(self):
        rng=np.random.default_rng(20261031)
        for i in range(100):
            x=float(rng.uniform(.04,1.3))
            r=float(rng.uniform(.08,.8))
            mu=float(rng.uniform(-.35,.35))
            sig=float(rng.uniform(.13,.8))
            T=float(rng.uniform(.1,15.))
            lam=float(rng.uniform(.001,.4))
            a=solve(x=x,r=r,mu=mu,sigma=sig,T=T,lam=lam,K=30)
            p=a.exact_count_probabilities.detach().numpy()
            self.assertFalse(np.isnan(p).any(),i)
            self.assertAlmostEqual(p.sum()+float(a.overflow_probability),1.,places=12)
            self.assertGreaterEqual(p.min(),-1e-14)

    def test_negative_domain_and_precision_refusal(self):
        invalid=[dict(K=0),dict(K=True),dict(r=0.),dict(x=0.),dict(sigma=0.),
                 dict(T=0.),dict(T=101.),dict(lam=-.1),dict(mu=.7),
                 dict(K=256,r=3.),dict(maximum_censored_tail=1.01)]
        for d in invalid:
            with self.subTest(case=d),self.assertRaises(ValueError):
                solve(**d)
        with self.assertRaises(TypeError):
            renewal_count_law(t(.5).float(),t(.4),t(0.),t(.3),t(2.),t(.1))
        with self.assertRaises(ValueError):
            renewal_count_law(t(.5),t(.4),t(float('nan')),t(.3),t(2.),t(.1))

if __name__=='__main__':
    unittest.main()
