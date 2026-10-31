import math
import unittest
import numpy as np
try:
 from .hx_stable import boundary_coefficients,equity_near_boundary
 from .hx_original import HXParams,closed_boundary,equity_green
 from .hx_a7 import equity_a7
except ImportError:
 from hx_stable import boundary_coefficients,equity_near_boundary
 from hx_original import HXParams,closed_boundary,equity_green
 from hx_a7 import equity_a7

class HXTaylorTests(unittest.TestCase):
 def test_matches_a7_and_independent_green_when_resolved(self):
    for p in (HXParams(),HXParams(sigma=.13,k=.025),HXParams(sigma=.30,delta=.04)):
        b=closed_boundary(p)
        e2,e3,e4=boundary_coefficients(p,b)
        self.assertTrue(all(math.isfinite(z) for z in (e2,e3,e4)))
        for x in (1e-4,3e-4,1e-3):
            v=b*math.exp(x)
            local=equity_near_boundary(x,p,b)
            expected=equity_a7(v,p,b)
            green=equity_green(v,b,p)
            self.assertAlmostEqual(local,green,delta=1e-6*max(1,abs(green)))
            self.assertAlmostEqual(local,expected,delta=1e-6*max(1,abs(expected)))
 def test_low_margin_fp32_direct_log_margin_representation(self):
    p=HXParams();b=closed_boundary(p)
    e2,e3,e4=boundary_coefficients(p,b)
    for x in (1e-5,1e-6,1e-7,1e-8):
        # Coefficients computed in f64, input state and polynomial in f32.
        xf=np.float32(x)
        local=float(xf*xf*(np.float32(.5*e2)+
                   xf*(np.float32(e3/6)+xf*np.float32(e4/24))))
        expected=equity_near_boundary(x,p,b)
        self.assertAlmostEqual(local/expected,1.,delta=5e-6)
    with self.assertRaises(ValueError):equity_near_boundary(.002,p,b)

if __name__=='__main__':unittest.main(verbosity=2)
