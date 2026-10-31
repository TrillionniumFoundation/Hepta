"""Frozen original-HX Monte Carlo sample distribution tests."""
import math
import unittest
import numpy as np
try:
    from .hx_original import HXParams,closed_boundary
    from .first_passage_mc import draw_first_passage_times,sample_bond_reference
except ImportError:
    from hx_original import HXParams,closed_boundary
    from first_passage_mc import draw_first_passage_times,sample_bond_reference


class OriginalHXMonteCarloTests(unittest.TestCase):
    def test_first_passage_finance_cash_flows_independent_of_cdf(self):
        # This panel was chosen before evaluation. Not an independent research
        # holdout, not a claim of an all-domain theorem.
        configs=[
            (HXParams(),.22,1.,10201),  # upward drift: chance of never hitting
            (HXParams(sigma=.46,r=.065,delta=.095,xi=2.,k=.025),.34,.8,10202),
            (HXParams(sigma=.3,r=.065,delta=.02,xi=0.,k=0.),.45,1.,10203),
            (HXParams(sigma=.2,r=.08,delta=.06,xi=2.,k=.015),.28,.6,10204), # zero log drift
        ]
        for p,x,tau,seed in configs:
            result=sample_bond_reference(x,tau,closed_boundary(p),p,
                                         seed=seed,sample_size=120_000)
            with self.subTest(drift=result['drift'],seed=seed):
                for key,val in result['statistics'].items():
                    # Exploratory broad 6-SE sanity envelope + fp floor;
                    # neither a preregistered CI nor a global error guarantee.
                    self.assertLess(val.absolute_error,
                                    6*val.standard_error+1e-10,(key,val))
                    self.assertTrue(math.isfinite(val.estimated))
                    self.assertTrue(math.isfinite(val.analytic))
                    self.assertTrue(math.isfinite(val.signed_z_score))

    def test_eventual_hit_mixture_positive_negative_and_zero_drift(self):
        g=np.random.default_rng(29871)
        for p,x in [(HXParams(),.4),
                    (HXParams(sigma=.45,r=.055,delta=.09),.4),
                    (HXParams(sigma=.2,r=.08,delta=.06),.4)]:
            times=draw_first_passage_times(x,p,g,150_000)
            mu=p.r-p.delta-.5*p.sigma**2
            expected=math.exp(-2*mu*x/p.sigma**2) if mu>0 else 1.
            freq=np.isfinite(times).mean()
            self.assertLess(abs(freq-expected),.012)
            self.assertTrue(np.all(times[times!=np.inf]>0))

    def test_reject_invalid_parameters(self):
        p=HXParams();g=np.random.default_rng(1)
        for x,n in [(0.,100),(-1.,100),(.5,1),(.5,1000001)]:
            with self.assertRaises(ValueError):
                draw_first_passage_times(x,p,g,n)
        with self.assertRaises(ValueError):
            sample_bond_reference(.3,p.maturity+1,100,p,seed=1)
        with self.assertRaises(ValueError):
            sample_bond_reference(.3,.4,100,p,seed=-4)

if __name__=='__main__':unittest.main()
