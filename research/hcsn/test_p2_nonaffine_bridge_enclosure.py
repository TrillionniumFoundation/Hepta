"""Cross-check conditional split-bridge integral vs exact-in-time midpoint MC."""
import math
import unittest
try:
    from .p2_nonaffine_bridge_enclosure import (TentBridge,flat_affine_hit,
        midpoint_hit_lower_bound,tent_hit_quadrature,tent_hit_bridge_mc)
except ImportError:
    from p2_nonaffine_bridge_enclosure import (TentBridge,flat_affine_hit,
        midpoint_hit_lower_bound,tent_hit_quadrature,tent_hit_bridge_mc)

class NonaffineBridgeTests(unittest.TestCase):
    def test_flat_matches_reflection(self):
        for a,b,s,t in [(.4,.4,.4,1.),(.2,.8,.6,1.5),(.7,.3,.9,2.)]:
            p=TentBridge(a,b,t,s,0.)
            hit,err=tent_hit_quadrature(p)
            self.assertLess(abs(hit-flat_affine_hit(p)),max(1e-9,20*err))

    def test_tent_underestimate_witness(self):
        p=TentBridge()
        lower=midpoint_hit_lower_bound(p)
        hit,err=tent_hit_quadrature(p)
        self.assertAlmostEqual(flat_affine_hit(p),math.exp(-2),places=13)
        self.assertGreater(lower,.84)
        self.assertGreater(hit,.94)
        self.assertGreater(hit-flat_affine_hit(p),.80)
        self.assertGreaterEqual(hit+err,lower)

    def test_monotonic_height_and_midpoint_bound(self):
        values=[]
        for h in (0.,.2,.4,.6):
            p=TentBridge(height=h)
            hit,err=tent_hit_quadrature(p)
            self.assertGreaterEqual(hit+10*err,midpoint_hit_lower_bound(p))
            values.append(hit)
        self.assertTrue(all(x<y for x,y in zip(values,values[1:])))

    def test_independent_bridge_mc(self):
        for height in (0.,.4,.6):
            p=TentBridge(height=height)
            theoretical,_=tent_hit_quadrature(p)
            observed,se,_=tent_hit_bridge_mc(p,120_000,20261101)
            self.assertLess(abs(observed-theoretical),5*se+5e-5)

    def test_time_rescaling(self):
        p=TentBridge()
        q=TentBridge(horizon=10.,sigma=p.sigma/math.sqrt(10.))
        self.assertAlmostEqual(tent_hit_quadrature(p)[0],tent_hit_quadrature(q)[0],places=12)

    def test_reject_unqualified_inputs(self):
        for kw in ({'a':True},{'a':0.},{'b':float('nan')},
                   {'horizon':0.},{'sigma':float('inf')},{'height':-.1},
                   {'height':True}):
            with self.assertRaises(ValueError): TentBridge(**kw).validate()
        with self.assertRaises(ValueError):tent_hit_bridge_mc(TentBridge(),n=True)
        with self.assertRaises(ValueError):tent_hit_bridge_mc(TentBridge(),n=10)

if __name__=='__main__': unittest.main()
