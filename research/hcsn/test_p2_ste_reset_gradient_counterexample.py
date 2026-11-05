"""Independent, direct differentiation and finite-difference tests for P2 reset surrogate."""
from __future__ import annotations
import math
import unittest
from p2_ste_reset_gradient_counterexample import (torch_straight_through,
    hard_reset_forward, evaluate_case, evidence)

class TestSteResetGradientCounterexample(unittest.TestCase):
    def test_analytic_vs_autograd_signed_history(self):
        for old in (-30.,-8.,-1.,0.,1.,8.,30.):
            for target in (-2.,-1.,0.,1.,2.):
                x=torch_straight_through(.2,old,target)
                self.assertAlmostEqual(x['ste_gradient'],x['independent_analytic_ste_gradient'],places=11)
                self.assertEqual(x['reset'],1)

    def test_hard_forward_stays_constant_on_open_reset_region(self):
        for old in (-20.,-1.,1.,20.):
            y=[hard_reset_forward(w,old) for w in (.01,.1,.2,.5,1.,5.)]
            self.assertEqual(y,[0.]*len(y))

    def test_true_derivative_zero_surrogate_nonzero(self):
        x=evaluate_case(.2,8.,1.,0.)
        self.assertEqual(x['true_central_difference'],0.)
        self.assertGreater(x['ste_gradient'],3.)

    def test_sign_reversal_for_opposite_histories(self):
        plus=torch_straight_through(.2,8.,1.)
        minus=torch_straight_through(.2,-8.,1.)
        self.assertEqual(plus['forward_loss'],minus['forward_loss'])
        self.assertAlmostEqual(plus['ste_gradient'],-minus['ste_gradient'],places=12)

    def test_actual_hard_loss_worsens_on_gradient_step(self):
        x=evaluate_case(.2,8.,1.,.1)
        self.assertEqual(x['forward_loss'],1.)
        self.assertEqual(x['stepped_loss'],49.)
        self.assertGreater(x['loss_increase'],0.)
        self.assertEqual(x['stepped_reset'],0)

    def test_zero_old_state_no_phantom_gradient(self):
        x=torch_straight_through(.2,0.,1.)
        self.assertEqual(x['ste_gradient'],0.)

    def test_invalid_nonfinite_rejected(self):
        for bad in (math.nan,math.inf,-math.inf):
            with self.assertRaises(ValueError):hard_reset_forward(.2,bad)
            with self.assertRaises(ValueError):torch_straight_through(bad,1.,1.)

    def test_acceptance_fails_closed(self):
        data=evidence()
        self.assertFalse(data['full_hcsn_validated'])
        self.assertFalse(data['external_independent_attestation'])
        self.assertTrue(all(v=='OPEN' for v in data['p0_to_p6'].values()))
        self.assertEqual(data['strict_gate_exit_code'],2)
        self.assertFalse(data['production_activation'])

if __name__=='__main__':unittest.main()
