"""Independent numerical and pathwise checks; P0-P6 stay OPEN."""
import unittest
import numpy as np
from scipy.integrate import solve_ivp
from scipy.linalg import expm
from research.hcsn.p2_joint_input_hazard import parity_probability,parity_generator
from research.hcsn.p2_order_oblivious_hazard import (
    exposure,endpoint_distribution,online_endpoint,ordered_last_write_pair,
    balanced_pair_endpoint_ceiling
)

class OrderObliviousHazardTests(unittest.TestCase):
    def setUp(self):
        pair=ordered_last_write_pair()
        self.a,self.label_a=pair[0]
        self.b,self.label_b=pair[1]

    def test_true_order_labels_are_opposed(self):
        self.assertEqual((self.label_a,self.label_b),(1,0))
        self.assertNotEqual(self.a,self.b)

    def test_exact_exposure_order_invariance(self):
        for beta in (-1.8,-0.5,0.,0.7,1.8):
            with self.subTest(beta=beta):
                self.assertAlmostEqual(exposure(self.a,beta),exposure(self.b,beta),places=13)
                np.testing.assert_allclose(endpoint_distribution(self.a,beta),endpoint_distribution(self.b,beta),atol=2e-14,rtol=0)
                self.assertAlmostEqual(parity_probability(self.a,beta),parity_probability(self.b,beta),places=13)
                self.assertAlmostEqual(balanced_pair_endpoint_ceiling(self.a,self.b,beta),.5,places=12)

    def test_full_generator_is_a_shared_scalar_time_change(self):
        for beta,x in ((0.4,-1.1),(-0.8,1.5),(1.4,0.7)):
            np.testing.assert_allclose(parity_generator(((4.,.25),(.7,.07)),beta,x),
               np.exp(beta*x)*parity_generator(((4.,.25),(.7,.07)),0.,0.),rtol=3e-15,atol=2e-15)

    def test_independent_ode_not_using_expm(self):
        beta=1.4
        target=endpoint_distribution(self.a,beta)
        # Time-dependent Kolmogorov forward equation integrated independently.
        state=np.array([1.,0.,0.,0.]);q0=parity_generator(((4.,.25),(.7,.07)),0.,0.)
        for dt,x in self.a:
            def rhs(_,v):return np.exp(beta*x)*(v@q0)
            sol=solve_ivp(rhs,(0.,dt),state,rtol=2e-12,atol=2e-14,method='DOP853')
            self.assertTrue(sol.success);state=sol.y[:,-1]
        np.testing.assert_allclose(state,target,atol=3e-11,rtol=0)

    def test_same_seed_event_count_and_final_mode(self):
        for beta in (-1.1,0.,1.3):
            for seed in (11,23,37,101,2024,98765):
                with self.subTest(beta=beta,seed=seed):
                    self.assertEqual(online_endpoint(self.a,seed,beta),online_endpoint(self.b,seed,beta))

    def test_repeated_pairs_not_rescued_by_length(self):
        for copies in (1,3,10,40):
            for beta in (-1.2,0.3,1.5):
                a=self.a[:2]*copies+self.a[2:]
                b=self.b[:2]*copies+self.b[2:]
                self.assertAlmostEqual(balanced_pair_endpoint_ceiling(a,b,beta),.5,places=12)

    def test_illegal_exposure_rejected(self):
        from research.hcsn.p2_order_oblivious_hazard import exposure
        for segs in ([],[(0.,0.)],[(-1.,0.)],[(1.,float('nan'))],[(1.,float('inf'))]):
            with self.assertRaises(ValueError):exposure(segs,1.)
        with self.assertRaises(ValueError):exposure([(1.,1.)],9.)

if __name__=='__main__':unittest.main()
