"""Fail-closed tests for state-coupled free-boundary feedback counterexample."""
import math
import unittest

import numpy as np

try:
    from research.hcsn.p2_endogenous_feedback_bridge import (
        FeedbackBridge, exact_feedback_hit, invalid_frozen_sigma_hit,
        transformed_margin_hit, midpoint_quadrature, midpoint_bridge_mc,
        mp_reference)
except ModuleNotFoundError:
    from p2_endogenous_feedback_bridge import (
        FeedbackBridge, exact_feedback_hit, invalid_frozen_sigma_hit,
        transformed_margin_hit, midpoint_quadrature, midpoint_bridge_mc,
        mp_reference)


class FeedbackBridgeTest(unittest.TestCase):
    def test_pathwise_event_identity(self):
        x=np.array([-.4,0,.2,.4,1.0])
        for gain in (-.75,0.,.5,.75,.9):
            np.testing.assert_array_equal(x <= gain*x, x <= 0)

    def test_gain_invariance_of_true_hit(self):
        baseline=exact_feedback_hit(FeedbackBridge(gain=0.))
        for gain in (-.75,0.,.5,.75,.9):
            p=FeedbackBridge(gain=gain)
            self.assertAlmostEqual(exact_feedback_hit(p),baseline,places=15)
            self.assertAlmostEqual(transformed_margin_hit(p),baseline,places=15)

    def test_zero_gain_matches_deterministic_affine(self):
        p=FeedbackBridge(gain=0.)
        self.assertAlmostEqual(invalid_frozen_sigma_hit(p), exact_feedback_hit(p),places=15)

    def test_feedback_overestimate_example(self):
        p=FeedbackBridge(gain=.75)
        self.assertGreater(invalid_frozen_sigma_hit(p)-exact_feedback_hit(p),.7)

    def test_negative_gain_underestimate(self):
        p=FeedbackBridge(gain=-.75)
        self.assertGreater(exact_feedback_hit(p)-invalid_frozen_sigma_hit(p),.13)

    def test_midpoint_quadrature_independent(self):
        for a,b,sigma,T in ((.4,.4,.4,1.),(.2,.6,.7,.8),(.9,.3,.6,1.5)):
            p=FeedbackBridge(a=a,b=b,sigma=sigma,horizon=T)
            value,err=midpoint_quadrature(p)
            self.assertLess(abs(value-exact_feedback_hit(p)),max(1e-11,10*err))

    def test_mp_reference_independent(self):
        for p in (FeedbackBridge(gain=-.5),FeedbackBridge(gain=.75),
                  FeedbackBridge(a=.2,b=.6,horizon=.8,sigma=.7,gain=.9)):
            self.assertLess(abs(float(mp_reference(p))-exact_feedback_hit(p)),2e-15)

    def test_midpoint_mc_and_gain_invariance(self):
        rates=[]
        for gain in (-.5,.75):
            p=FeedbackBridge(gain=gain)
            observed,se,count=midpoint_bridge_mc(p,n=100_000,seed=81017)
            rates.append((observed,se,count))
            self.assertLess(abs(observed-exact_feedback_hit(p)),5*se+1e-3)
        self.assertEqual(rates[0],rates[1])

    def test_mc_reproducibility(self):
        p=FeedbackBridge()
        self.assertEqual(midpoint_bridge_mc(p,n=1000,seed=171),
                         midpoint_bridge_mc(p,n=1000,seed=171))

    def test_invalid_physical_inputs_rejected(self):
        bad=(dict(a=0),dict(b=-1),dict(sigma=float('nan')),
             dict(horizon=float('inf')),dict(gain=1.),
             dict(gain=True),dict(sigma=.01),dict(a=True))
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                FeedbackBridge(**item).validate()

    def test_invalid_mc_and_precision_rejected(self):
        p=FeedbackBridge()
        for n in (0,True,1.5,2_000_000):
            with self.assertRaises(ValueError):midpoint_bridge_mc(p,n=n)
        for dps in (20,True,200):
            with self.assertRaises(ValueError):mp_reference(p,dps=dps)

    def test_spatial_scale_invariance(self):
        p=FeedbackBridge(a=.2,b=.5,sigma=.3,gain=.7)
        q=FeedbackBridge(a=.4,b=1.,sigma=.6,gain=.7)
        self.assertAlmostEqual(exact_feedback_hit(p),exact_feedback_hit(q),places=14)


if __name__=='__main__': unittest.main()
