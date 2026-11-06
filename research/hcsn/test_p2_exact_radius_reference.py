import math
import unittest
from decimal import Decimal, localcontext
from fractions import Fraction
from p2_exact_radius_reference import E, R, exact_gap, exact_distance_decimal

class ExactRadiusReferenceTests(unittest.TestCase):
    def test_radius_is_above_exact_real_chord_distance(self):
        self.assertGreater(exact_gap(E, R), 0)
        with localcontext() as ctx:
            ctx.prec = 110
            d = Decimal(exact_distance_decimal(E))
            self.assertGreater(Decimal.from_float(R), d)
            self.assertLess(Decimal.from_float(math.nextafter(R, 0.0)), d)

    def test_gap_is_exact_positive_fraction(self):
        gap = exact_gap(E, R)
        self.assertIsInstance(gap, Fraction)
        self.assertGreater(gap.numerator, 0)
        self.assertGreater(gap.denominator, 0)

    def test_one_ulp_upper_radius_is_also_inside(self):
        self.assertGreater(exact_gap(E, math.nextafter(R, math.inf)), 0)

    def test_one_ulp_lower_radius_is_outside(self):
        self.assertLess(exact_gap(E, math.nextafter(R, 0.0)), 0)

if __name__ == '__main__':
    unittest.main(verbosity=2)
