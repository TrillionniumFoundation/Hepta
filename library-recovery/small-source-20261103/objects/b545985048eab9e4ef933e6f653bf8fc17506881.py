import unittest
import numpy as np
from hcsn_p0_p6_20261031.regenerative_qvi import QVIConfig,solve_qvi,reset_path,build_generator

class RegenerativeQVITests(unittest.TestCase):
    def test_generator_is_valid(self):
        xs,Q,j=build_generator(QVIConfig())
        a=Q.toarray(); self.assertLess(np.max(abs(a.sum(axis=1))),1e-10)
        self.assertGreaterEqual(np.min(a-np.diag(np.diag(a))),0)
        self.assertTrue(0<j<len(xs)-1)
    def test_bellman_and_policy(self):
        z=solve_qvi(); self.assertLess(z['residual_sup'],1e-7)
        self.assertTrue(np.any(z['policy']))
        self.assertFalse(z['policy'][z['reset_index']])
        self.assertLess(np.max(z['intervention']),1e-7)
        self.assertLess(np.max(z['continuation']),1e-7)
    def test_resolution_stability(self):
        coarse=solve_qvi(QVIConfig(n=401)); fine=solve_qvi(QVIConfig(n=801))
        # Interior values interpolate at the same physical x, not grid indices.
        e=max(abs(np.interp(coarse['xs'][10:-10],fine['xs'],fine['u'])-coarse['u'][10:-10]))
        self.assertLess(e,.10)
    def test_repeated_reset_semantics(self):
        p=QVIConfig(); z=solve_qvi(p)
        idx=int(np.flatnonzero(z['policy'])[0]); s=reset_path(p,[idx,idx,idx])
        self.assertEqual(s,[(z['reset_index'],True)]*3)
        self.assertFalse(reset_path(p,[z['reset_index']])[0][1])
    def test_rejection(self):
        with self.assertRaises(ValueError):solve_qvi(QVIConfig(reset_cost=-1))
if __name__=='__main__':unittest.main()
