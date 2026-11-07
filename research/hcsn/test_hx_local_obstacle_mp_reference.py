"""Independent 50-digit quadrature excludes binary64 cancellation explanation."""
import unittest

try:
    from .hx_original import HXParams
    from .test_hx_local_obstacle_sign import HIGH_LIQUIDITY
    from .hx_local_obstacle_mp_reference import mp_first_passage_sign
except ImportError:
    from hx_original import HXParams
    from test_hx_local_obstacle_sign import HIGH_LIQUIDITY
    from hx_local_obstacle_mp_reference import mp_first_passage_sign


class HXLocalObstructionMPTests(unittest.TestCase):
    def test_high_liquidity_counterexample_confirmed_at_50_digits(self):
        d=mp_first_passage_sign(HIGH_LIQUIDITY,decimal_digits=50)
        self.assertTrue(d['negative_curvature_observed'])
        self.assertAlmostEqual(float(d['boundary']),197.52085498628088,delta=1e-10)
        self.assertAlmostEqual(float(d['boundary_cashflow']),4.16684478880852,delta=1e-12)
        self.assertAlmostEqual(float(d['boundary_log_curvature']),-208.3422394404259,delta=1e-11)
        self.assertLess(float(d['recovery_over_face']),.8)
        self.assertFalse(d['outward_rounded_intervals'])
        self.assertFalse(d['globally_certified'])
        self.assertFalse(d['production_activation'])

    def test_paper_baseline_positive_curvature_only(self):
        d=mp_first_passage_sign(HXParams(),decimal_digits=50)
        self.assertFalse(d['negative_curvature_observed'])
        self.assertAlmostEqual(float(d['boundary']),67.44151539060374,delta=1e-10)
        self.assertLess(float(d['boundary_cashflow']),-20)
        self.assertFalse(d['globally_certified'])

    def test_invalid_precision_must_refuse(self):
        for prec in (0,20,101,True,None):
            with self.assertRaises(ValueError):mp_first_passage_sign(HXParams(),decimal_digits=prec)

if __name__=='__main__':unittest.main(verbosity=2)
