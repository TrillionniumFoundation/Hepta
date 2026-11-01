"""Independent off-center apex Brownian-bridge scientific negative controls."""
import math
import unittest
try:
    from .p2_offcenter_tent_reference import (OffcenterTent, hit_quadrature,
                                               hit_mp_closed_form, hit_bridge_mc)
except ImportError:
    from p2_offcenter_tent_reference import (OffcenterTent, hit_quadrature,
                                            hit_mp_closed_form, hit_bridge_mc)


class OffcenterTentTests(unittest.TestCase):
    def test_mpmath_matches_independent_quadrature(self):
        for a,b,s,h,c in [(.2,.8,.4,.45,.1),(.2,.8,.4,.45,.9),
                          (.4,.4,.4,.6,.5),(.4,.4,.4,.2,.2),
                          (.7,.3,.9,.1,.75),(.15,.9,.4,.45,.25)]:
            p=OffcenterTent(a,b,1.0,s,h,c)
            mp=hit_mp_closed_form(p)
            q,err=hit_quadrature(p)
            self.assertLess(abs(q-mp),max(1e-11,15*err))

    def test_flat_boundary_apex_invariance(self):
        for c in (.1,.25,.5,.75,.9):
            p=OffcenterTent(height=0.,apex_fraction=c)
            expected=math.exp(-2*p.a*p.b/(p.sigma**2*p.horizon))
            self.assertAlmostEqual(hit_mp_closed_form(p),expected,places=12)

    def test_offcenter_witness_invalidates_midpoint_surrogate(self):
        early=hit_mp_closed_form(OffcenterTent(apex_fraction=.1))
        center=hit_mp_closed_form(OffcenterTent(apex_fraction=.5))
        late=hit_mp_closed_form(OffcenterTent(apex_fraction=.9))
        self.assertGreater(early,.98)
        self.assertLess(late,.48)
        self.assertGreater(early-center,.24)
        self.assertGreater(center-late,.23)

    def test_symmetric_endpoints_time_reversal(self):
        for h in (0.,.2,.6):
            for c in (.1,.25,.4):
                p=OffcenterTent(a=.4,b=.4,height=h,apex_fraction=c)
                q=OffcenterTent(a=.4,b=.4,height=h,apex_fraction=1-c)
                self.assertAlmostEqual(hit_mp_closed_form(p),hit_mp_closed_form(q),places=12)

    def test_reversal_with_asymmetric_endpoints(self):
        p=OffcenterTent()
        q=OffcenterTent(a=p.b,b=p.a,height=p.height,apex_fraction=1-p.apex_fraction)
        self.assertAlmostEqual(hit_mp_closed_form(p),hit_mp_closed_form(q),places=12)

    def test_height_monotonicity_and_flat_floor(self):
        for c in (.1,.5,.9):
            values=[hit_mp_closed_form(OffcenterTent(height=h,apex_fraction=c))
                    for h in (0.,.2,.4,.6)]
            self.assertTrue(all(x<y for x,y in zip(values,values[1:])))

    def test_physical_time_and_diffusion_rescaling(self):
        p=OffcenterTent()
        q=OffcenterTent(horizon=4.,sigma=.2)
        self.assertAlmostEqual(hit_mp_closed_form(p),hit_mp_closed_form(q),places=12)

    def test_conditional_midpoint_monte_carlo(self):
        for c in (.1,.5,.9):
            p=OffcenterTent(apex_fraction=c)
            exact=hit_mp_closed_form(p)
            observed,se,_=hit_bridge_mc(p,n=150_000,seed=20261101)
            self.assertLess(abs(observed-exact),5*se+1/150_000)

    def test_reject_unqualified(self):
        for kw in ({'a':True},{'a':0.},{'b':float('nan')},
                   {'sigma':0.},{'horizon':float('inf')},
                   {'height':-.1},{'apex_fraction':0.},{'apex_fraction':1.},
                   {'apex_fraction':True}):
            with self.assertRaises(ValueError): OffcenterTent(**kw).validate()
        for n in (True,0,1_000_001):
            with self.assertRaises(ValueError): hit_bridge_mc(OffcenterTent(),n=n)
        for dps in (True,20,300):
            with self.assertRaises(ValueError): hit_mp_closed_form(OffcenterTent(),dps=dps)


if __name__=='__main__': unittest.main()
