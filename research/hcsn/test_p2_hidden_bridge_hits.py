"""Independent reflection, quadrature, Monte Carlo, streaming and bad-input tests."""
import math
import unittest
import numpy as np
from scipy.integrate import quad
from scipy.stats import norm
from .p2_hidden_bridge_hits import (conditional_hidden_hit, first_hit_cdf,
    conditional_path_risk, BridgeRiskState, missed_endpoint_example)


class HiddenBridgeHitTests(unittest.TestCase):
    def test_endpoint_detector_misses_half_of_zero_drift_crossings(self):
        w=missed_endpoint_example()
        self.assertAlmostEqual(w['continuous_first_hit_probability'],
                               2*w['endpoint_only_hit_probability'],places=14)
        self.assertGreater(w['probability_mass_missed_by_endpoint_only'],.15)
        self.assertEqual(w['scientific_gate'],'OPEN')

    def test_integrate_conditional_bridge_against_independent_reflection(self):
        # Independent unconditional first-hit law, not repeated bridge identity.
        cases=[(.4,0.,.4,1.),(.63,.17,.65,.8),(.3,-.25,.52,1.5),(.9,.3,.8,2.)]
        for start,drift,sigma,t in cases:
            mu=start+drift*t;sd=sigma*math.sqrt(t)
            integrand=lambda end: norm.pdf(end,loc=mu,scale=sd)*conditional_hidden_hit(start,end,t,sigma)
            integrated=quad(integrand,-20.,0.,epsabs=2e-11,epsrel=1e-11)[0]+quad(
                integrand,0.,20.,epsabs=2e-11,epsrel=1e-11)[0]  # omitted Gaussian tails < 1e-40
            self.assertAlmostEqual(integrated,first_hit_cdf(start,drift,sigma,t),places=10)

    def test_independent_endpoint_mc_with_bridge_bernoullis(self):
        rng=np.random.default_rng(492001)
        x0,mu,sigma,t=.4,-.12,.5,1.4
        n=180000
        ends=x0+mu*t+sigma*math.sqrt(t)*rng.standard_normal(n)
        # Different implementation: sample bridge minima using independent U.
        u=rng.uniform(size=n)
        hits=(ends<=0)|(u<np.exp(-2*x0*np.maximum(ends,0)/(sigma*sigma*t)))
        empirical=float(hits.mean());expected=first_hit_cdf(x0,mu,sigma,t)
        se=math.sqrt(expected*(1-expected)/n)
        self.assertLess(abs(empirical-expected),5*se)

    def test_observation_prefix_and_chunk_equivalence(self):
        rng=np.random.default_rng(992)
        margin=.6+np.cumsum(rng.normal(0,.03,size=(4,100)),axis=1)
        times=np.tile(np.cumsum(rng.uniform(.2,1.5,100))[None,:],(4,1))
        whole,st=conditional_path_risk(margin.astype(np.float64),times.astype(np.float64),sigma=.8)
        a,s=conditional_path_risk(margin[:,:17],times[:,:17],sigma=.8)
        b,s=conditional_path_risk(margin[:,17:65],times[:,17:65],sigma=.8,state=s)
        c,sc=conditional_path_risk(margin[:,65:],times[:,65:],sigma=.8,state=s)
        self.assertTrue(np.array_equal(whole,np.concatenate([a,b,c],axis=1)))
        self.assertTrue(np.array_equal(sc.log_survival,st.log_survival))
        # Same prefix under any future continuation.
        changed=margin.copy();changed[:,20:]=99.
        prefix,_=conditional_path_risk(changed[:,:17],times[:,:17],sigma=.8)
        self.assertTrue(np.array_equal(prefix,a))

    def test_exact_two_gap_product_and_time_unit_scaling(self):
        x=np.array([[.45,.62,.33]],dtype=np.float64)
        t=np.array([[0.,1.,3.]],dtype=np.float64)
        got,_=conditional_path_risk(x,t,sigma=.4)
        p1=conditional_hidden_hit(.45,.62,1.,.4)
        p2=conditional_hidden_hit(.62,.33,2.,.4)
        self.assertAlmostEqual(got[0,-1],1-(1-p1)*(1-p2),places=14)
        ms,_=conditional_path_risk(x,t*1000.,sigma=.4/math.sqrt(1000))
        self.assertTrue(np.allclose(got,ms,rtol=2e-14,atol=2e-14))

    def test_affine_barrier_translation_and_slope(self):
        # X(t)=d(t)+b(t). If b is affine, exact risk depends only on d(t).
        margins=np.array([[.8,.9,.74,.7]],dtype=np.float64)
        times=np.array([[0.,.3,1.,1.5]],dtype=np.float64)
        base,_=conditional_path_risk(margins,times,sigma=.66)
        slope=.33;barrier=-.2+slope*times
        observed=(margins+barrier)-barrier
        moved,_=conditional_path_risk(observed,times,sigma=.66)
        self.assertTrue(np.array_equal(base,moved))

    def test_conditional_derivatives_positive_interior(self):
        a,b,t,s=.35,.49,1.7,.8
        val=conditional_hidden_hit(a,b,t,s)
        h=1e-5
        fd=(conditional_hidden_hit(a+h,b,t,s)-conditional_hidden_hit(a-h,b,t,s))/(2*h)
        self.assertAlmostEqual(fd,-2*b/(s*s*t)*val,delta=1e-9)

    def test_stopping_and_extreme_tail_stability(self):
        m=np.array([[.0,1.,1.],[3.,3.,3.],[.5,.5,.5]],dtype=np.float64)
        t=np.array([[0.,1.,2.]]*3,dtype=np.float64)
        y,s=conditional_path_risk(m,t,sigma=.1)
        self.assertTrue((y>=0).all() and (y<=1).all())
        self.assertEqual(y[0,0],1.)
        self.assertTrue((y[0,:]==1.).all())
        self.assertTrue((y[1,:]==0.).all())

    def test_reject_noncausal_malformed_and_corrupt_state(self):
        x=np.array([[.3,.4,.5]],dtype=np.float64)
        t=np.array([[0.,1.,2.]],dtype=np.float64)
        cases=[(x.astype(np.float32),t),(x,t.astype(np.float32)),
               (x,np.array([[0.,0.,2.]])),(x,np.array([[0.,-1.,2.]])),
               (np.array([[.3,np.nan,.2]]),t),(x,t[:,:2])]
        for a,b in cases:
            with self.assertRaises(ValueError): conditional_path_risk(a,b,sigma=.5)
        for sigma in (0.,-1.,float('nan'),True,100.):
            with self.assertRaises(ValueError): conditional_path_risk(x,t,sigma=sigma)
        _,s=conditional_path_risk(x,t,sigma=.5)
        with self.assertRaises(ValueError):
            conditional_path_risk(x,t,sigma=.5,state=s)
        invalid=BridgeRiskState(s.last_margin,s.last_time,np.array([.1],dtype=np.float64))
        with self.assertRaises(ValueError):conditional_path_risk(x,t+3.,sigma=.5,state=invalid)

    def test_not_inferred_spike_or_certified_qvi(self):
        x=np.array([[.4,.5]],dtype=np.float64);t=np.array([[0.,1.]],dtype=np.float64)
        y,_=conditional_path_risk(x,t,sigma=.4)
        self.assertGreater(y[0,1],0.)
        self.assertLess(y[0,1],1.)
        self.assertFalse(hasattr(y,'requires_grad'))

if __name__=='__main__': unittest.main()
