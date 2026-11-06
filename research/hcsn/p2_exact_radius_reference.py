"""Independent standard-library rational/Decimal witness for the P2 radius edge."""
from decimal import Decimal, localcontext
from fractions import Fraction
import json
from pathlib import Path

E = 0.01672897773676785
R = 0.016727222397810555

def exact_gap(e: float, radius: float) -> Fraction:
    ef = Fraction.from_float(e)
    rf = Fraction.from_float(radius)
    # For a=(1,0), b=(1,e), d^2 = 2 - 2/sqrt(1+e^2).
    # d <= r iff (2-r^2)^2 * (1+e^2) <= 4 (all sides positive).
    return Fraction(4, 1) - (2 - rf * rf) ** 2 * (1 + ef * ef)

def exact_distance_decimal(e: float, precision: int = 110) -> str:
    with localcontext() as ctx:
        ctx.prec = precision
        x = Decimal.from_float(e)
        d2 = Decimal(2) - Decimal(2) / (Decimal(1) + x * x).sqrt()
        return format(d2.sqrt(), f'.{precision-5}g')

def build() -> dict:
    gap = exact_gap(E, R)
    lower = Fraction.from_float(__import__('math').nextafter(R, 0.0))
    upper = Fraction.from_float(__import__('math').nextafter(R, __import__('math').inf))
    exact_d = Decimal(exact_distance_decimal(E))
    with localcontext() as ctx:
        ctx.prec = 110
        radius_dec = Decimal.from_float(R)
        lower_dec = Decimal.from_float(__import__('math').nextafter(R, 0.0))
    return {
        'schema': 'hcsn.p2-exact-radius-python-reference.v1',
        'method': 'Python stdlib Fraction exact binary64 rationals + Decimal high-precision square root',
        'a': [1.0, 0.0],
        'b': [1.0, E],
        'radius': R,
        'exact_distance_decimal': str(exact_d),
        'radius_minus_exact_distance_positive': radius_dec > exact_d,
        'exact_distance_minus_nextdown_radius_positive': exact_d > lower_dec,
        'exact_squared_inequality_gap_numerator': str(gap.numerator),
        'exact_squared_inequality_gap_denominator': str(gap.denominator),
        'exact_squared_inequality_gap_positive': gap > 0,
        'radius_nextdown_fraction_numerator': str(lower.numerator),
        'radius_nextdown_fraction_denominator': str(lower.denominator),
        'radius_nextup_fraction_numerator': str(upper.numerator),
        'radius_nextup_fraction_denominator': str(upper.denominator),
        'independent_acceptance': False,
        'scope': 'two-dimensional exact mathematical witness only; not trained HCSN or P0-P6 acceptance'
    }

if __name__ == '__main__':
    print(json.dumps(build(), indent=2, sort_keys=True))
