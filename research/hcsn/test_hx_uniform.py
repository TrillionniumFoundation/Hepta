"""P0 deterministic degeneracy, local near-boundary, and error-guard tests."""
import math
import unittest
try:
 from .hx_original import HXParams,closed_boundary,equity_green
 from .hx_uniform import equity_logmargin
 from .hx_stable import equity_near_boundary
except ImportError:
 from hx_original import HXParams,closed_boundary,equity_green
 from hx_uniform import equity_logmargin
 from hx_stable import equity_near_boundary

class HXUniformTests(unittest.TestCase):
 def test_exact_zero_liquidity_and_removable_singular_limit(self):
    for xk in (0.,1e-9,1e-7,1e-5,1e-3):
        p=HXParams(k=xk,xi=1.)
        b=closed_boundary(p)
        for x in (.03,.2,.5,1.2):
            data=equity_logmargin(x,p,boundary=b)
            g=equity_green(b*math.exp(x),b,p)
            self.assertLess(abs(data.equity-g),2e-7*max(1.,abs(g)))
            if xk==0:self.assertEqual(data.method,'quadrature_green_limit')
 def test_zero_continuous_boundary_and_taylor_provenance(self):
    p=HXParams();b=closed_boundary(p)
    for x in (-.1,0.):
        self.assertEqual(equity_logmargin(x,p,boundary=b).equity,0.)
    for x in (1e-9,1e-7,1e-5,1e-4,1e-3):
        data=equity_logmargin(x,p,boundary=b)
        self.assertEqual(data.method,'pde_local_series')
        self.assertGreaterEqual(data.equity,0.)
        self.assertAlmostEqual(data.equity,equity_near_boundary(x,p,b),places=11)
    self.assertLess(equity_logmargin(1e-6,p,boundary=b).equity,1e-8)
 def test_refusal_and_smooth_input(self):
    p=HXParams()
    for x in (float('nan'),float('inf'),-2.5,9.):
        with self.assertRaises(ValueError):equity_logmargin(x,p)
    with self.assertRaises(ValueError):equity_logmargin(.01,p,singular_tol=-1.)
    self.assertFalse(equity_logmargin(.01,p).method=='pde_local_series')

if __name__=='__main__':unittest.main()
