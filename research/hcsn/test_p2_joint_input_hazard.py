"""Independent ODE and explicit simulation checks for a limited input hazard."""
import math
import unittest
import numpy as np
from scipy.integrate import solve_ivp
from research.hcsn.p2_joint_input_hazard import (
 DEFAULT_RATES,InputHazardClock,checked_rates,marked_rates,
 parity_generator,parity_probability,task_parity,
)


def ode_parity_reference(segments,beta,rates=DEFAULT_RATES):
    state=np.array([1.,0.,0.,0.])
    for duration,x in segments:
        # Compute separately from the candidate transition exponentiation.
        r=marked_rates(rates,beta,x)
        def rhs(t,y):
            z=np.zeros(4)
            for p in (0,1):
                for i in (0,1):
                    m=2*p+i
                    z[m]-=(r[i,0]+r[i,1])*y[m]
                    for j in (0,1):z[2*(1-p)+j]+=r[i,j]*y[m]
            return z
        sol=solve_ivp(rhs,(0.,duration),state,rtol=3e-12,atol=2e-13)
        if not sol.success:raise RuntimeError(sol.message)
        state=sol.y[:,-1]
    return float(state[2:].sum())


class TestInputHazard(unittest.TestCase):
    def test_generator_conserves_mass_including_same_mode_mark(self):
        for x in (-1.5,0.,1.5):
            Q=parity_generator(DEFAULT_RATES,0.8,x)
            np.testing.assert_allclose(Q.sum(axis=1),0.,atol=2e-15)
            self.assertTrue(np.all(Q[~np.eye(4,dtype=bool)]>=0))

    def test_independent_ode_vs_finite_state_matrix(self):
        for beta in (-1.2,0.,0.85):
            for seg in ([ (0.75,-0.8)],[(0.3,-.7),(.7,1.1)],[(0.25,1.5),(.25,-1.5),(1.,0.)]):
                self.assertAlmostEqual(parity_probability(seg,beta),ode_parity_reference(seg,beta),delta=2e-10)

    def test_observation_refinement_preserves_event_times(self):
        for seed in (11,23,37,43):
            a=InputHazardClock(seed,0.7);b=InputHazardClock(seed,0.7)
            a.advance(0.,4.,.4)
            for k in range(64): b.advance(k/16.,(k+1)/16.,.4)
            self.assertEqual(len(a.events),len(b.events))
            self.assertEqual([(u,v) for _,u,v in a.events],[(u,v) for _,u,v in b.events])
            for x,y in zip(a.events,b.events):self.assertAlmostEqual(x[0],y[0],delta=2e-12)

    def test_future_input_does_not_change_prefix(self):
        a=InputHazardClock(117,.8);b=InputHazardClock(117,.8)
        p=a.advance(0.,2.,.2);q=b.advance(0.,2.,.2)
        self.assertEqual(p,q)
        a.advance(2.,4.,-1.5);b.advance(2.,4.,1.5)
        self.assertEqual(p,q)

    def test_input_changes_physical_event_intensity(self):
        lo=parity_probability([(0.2,-1.5)],1.0)
        hi=parity_probability([(0.2,1.5)],1.0)
        self.assertGreater(hi,lo+.1)

    def test_monte_carlo_vs_exact_parity(self):
        n=4000
        for beta in (.7,-.5):
            for seg in ([(.6,0.4)],[(.3,-.7),(.5,.5)]):
                expected=parity_probability(seg,beta)
                counts=sum(task_parity(seg,seed+10**6,beta) for seed in range(n))
                se=math.sqrt(expected*(1-expected)/n)
                self.assertLess(abs(counts/n-expected),5*se+2/n)

    def test_out_of_domain_and_atomic_budget_failure(self):
        for invalid in (((1.,),(.7,.2)), ((0.,1.),(.7,.2)),((float('nan'),1.),(.7,.2))):
            with self.assertRaises(ValueError):checked_rates(invalid)
        with self.assertRaises(ValueError):parity_probability([],0.)
        with self.assertRaises(ValueError):parity_probability([(0.,1.)],0.)
        with self.assertRaises(ValueError):parity_probability([(1.,float('nan'))],.1)
        with self.assertRaises(ValueError):InputHazardClock(True,.1)
        a=InputHazardClock(11,1.0,budget=1)
        with self.assertRaisesRegex(ValueError,'budget'):a.advance(0.,5.,1.)
        self.assertEqual((a.end,a.mode,len(a.events)),(0.,0,0))
        a.budget=10000;a.advance(0.,5.,1.)
        b=InputHazardClock(11,1.0);b.advance(0.,5.,1.)
        self.assertEqual(a.events,b.events)

if __name__=='__main__': unittest.main()
